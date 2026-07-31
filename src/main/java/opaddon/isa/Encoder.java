package opaddon.isa;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Binary encoder/decoder for the custom ISA instruction stream.
 *
 * Format: [opcode_byte] [operands...]
 * Operands are signed LEB128 varints for compactness.
 * Multi-byte values (long/double) are stored as raw 8 bytes following a marker.
 */
public final class Encoder {

    private Encoder() {}

    // --- Encode ---

    /**
     * Encode a list of instructions into a byte array.
     */
    public static byte[] encode(List<Instruction> instructions) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        for (Instruction insn : instructions) {
            buf.write(insn.opcode().code() & 0xFF);
            for (long operand : insn.operands()) {
                writeSignedLeb128(buf, operand);
            }
        }
        return buf.toByteArray();
    }

    // --- Decode ---

    /**
     * Decode a byte array into a list of instructions.
     */
    public static List<Instruction> decode(byte[] program) {
        List<Instruction> instructions = new ArrayList<>();
        int pc = 0;
        while (pc < program.length) {
            int opByte = program[pc++] & 0xFF;
            Opcode opcode;
            try {
                opcode = Opcode.fromCode((byte) opByte);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                    "Unknown opcode 0x" + Integer.toHexString(opByte) + " at pc=" + (pc - 1), e);
            }

            int operandCount = operandCount(opcode);
            long[] operands = new long[operandCount];
            for (int i = 0; i < operandCount; i++) {
                long[] result = readSignedLeb128(program, pc);
                operands[i] = result[0];
                pc = (int) result[1];
            }
            instructions.add(new Instruction(opcode, operands));
        }
        return instructions;
    }

    /**
     * Encode instructions with exception handler header and optional opcode shuffle.
     *
     * Format:
     *   [handler_count varint]
     *   [handler*4 varints (each padded to 5 bytes for fixed size)]
     *   [shuffle_flag varint: 0=identity, 1=shuffled]
     *   [if flag==1: reverse_mapping[256] bytes]
     *   [instructions with (possibly shuffled) opcodes...]
     */
    public static byte[] encodeWithHeader(List<Instruction> instructions, int[][] handlers,
                                           byte[] forwardMapping, byte[] reverseMapping) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // Exception handler count + entries
        writeSignedLeb128(buf, handlers.length);
        for (int[] h : handlers) {
            for (int f = 0; f < 4; f++) {
                writeFixedLeb128(buf, h[f]); // 5-byte fixed width
            }
        }

        // Shuffle flag + reverse mapping
        boolean shuffled = reverseMapping != null;
        writeSignedLeb128(buf, shuffled ? 1 : 0);
        if (shuffled) {
            for (int i = 0; i < 256; i++) {
                buf.write(reverseMapping[i] & 0xFF);
            }
        }

        // Instructions with (possibly shuffled) opcodes
        for (Instruction insn : instructions) {
            byte opByte = insn.opcode().code();
            if (forwardMapping != null) {
                opByte = forwardMapping[opByte & 0xFF];
            }
            buf.write(opByte & 0xFF);
            for (long operand : insn.operands()) {
                writeSignedLeb128(buf, operand);
            }
        }
        return buf.toByteArray();
    }

    /** Write a 32-bit value as exactly 5 bytes of LEB128 (padded with 0x80 bytes). */
    private static void writeFixedLeb128(ByteArrayOutputStream buf, int value) {
        for (int i = 0; i < 4; i++) {
            buf.write((int) ((value & 0x7F) | 0x80)); // high bit set = more bytes
            value >>>= 7;
        }
        buf.write(value & 0x7F); // final byte, high bit clear
    }

    /** Backward-compatible encode without shuffle */
    public static byte[] encodeWithHeader(List<Instruction> instructions, int[][] handlers) {
        return encodeWithHeader(instructions, handlers, null, null);
    }

    /**
     * Compute the size of the header (handlers + shuffle) in bytes.
     */
    public static int headerSize(int handlerCount, boolean hasShuffle) {
        int size = varintSize(handlerCount);
        for (int i = 0; i < handlerCount; i++) {
            size += 4 * 5; // conservative: max 5 bytes per varint per handler field
        }
        size += 1; // shuffle flag varint (0 or 1 = 1 byte)
        if (hasShuffle) {
            size += 256; // reverse mapping table
        }
        return size;
    }

    /** Backward-compatible header size query */
    public static int headerSize(int handlerCount) {
        return headerSize(handlerCount, false);
    }

    private static int varintSize(long value) {
        int size = 0;
        while (true) {
            size++;
            byte b = (byte) (value & 0x7F);
            value >>= 7;
            if ((value == 0 && (b & 0x40) == 0) || (value == -1 && (b & 0x40) != 0)) break;
        }
        return size;
    }

    /**
     * Program size in bytes after encoding.
     */
    public static int encodedSize(List<Instruction> instructions) {
        return encode(instructions).length;
    }

    // --- LEB128 ---

    /**
     * Write a signed 64-bit value as signed LEB128.
     */
    static void writeSignedLeb128(ByteArrayOutputStream buf, long value) {
        boolean more = true;
        while (more) {
            byte b = (byte) (value & 0x7F);
            value >>= 7;
            // Sign extend the 7th bit to check if we need more bytes
            if ((value == 0 && (b & 0x40) == 0) || (value == -1 && (b & 0x40) != 0)) {
                more = false;
            } else {
                b |= 0x80;
            }
            buf.write(b);
        }
    }

    /**
     * Read a signed LEB128 value. Returns {value, newPosition}.
     */
    static long[] readSignedLeb128(byte[] data, int offset) {
        long result = 0;
        int shift = 0;
        int pos = offset;
        byte b;
        do {
            b = data[pos++];
            result |= (long) (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);

        // Sign extend
        if ((b & 0x40) != 0) {
            result |= -(1L << shift);
        }

        return new long[]{result, pos};
    }

    // --- Operand counts ---

    private static int operandCount(Opcode op) {
        switch (op) {
            case ICONST: case LDC:
            case ILOAD: case LLOAD: case FLOAD: case DLOAD: case ALOAD:
            case ISTORE: case LSTORE: case FSTORE: case DSTORE: case ASTORE:
            case IFEQ: case IFNE: case IFLT: case IFGE: case IFGT: case IFLE:
            case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE:
            case IF_ICMPGT: case IF_ICMPLE:
            case IF_ACMPEQ: case IF_ACMPNE:
            case IFNULL: case IFNONNULL:
            case GOTO:
            case INVOKESTATIC: case INVOKEVIRTUAL: case INVOKESPECIAL: case INVOKEINTERFACE:
            case GETFIELD: case PUTFIELD: case GETSTATIC: case PUTSTATIC:
            case NEW: case NEWARRAY: case ANEWARRAY:
            case CHECKCAST: case INSTANCEOF:
                return 1;
            case MULTIANEWARRAY:
                return 2; // typeIdx, dimensions
            case LCONST: case DCONST:
                return 1; // stored as single varint (the bits of the long/double)
            case FCONST:
                return 1; // float bits stored as varint
            default:
                return 0;
        }
    }
}
