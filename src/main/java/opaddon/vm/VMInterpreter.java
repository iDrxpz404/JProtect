package opaddon.vm;

import opaddon.isa.Opcode;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Embedded stack-machine interpreter for the custom ISA.
 *
 * Thread-safe: all shared mutable state uses ConcurrentHashMap or ThreadLocal.
 * Multiple virtualized methods can execute concurrently without interference.
 */
public final class VMInterpreter {

    // --- Thread-safe reflective caches ---
    private static final ConcurrentHashMap<String, Method> methodCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Field> fieldCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Constructor<?>> ctorCache = new ConcurrentHashMap<>();

    // --- Thread-safe monitor tracking ---
    // Maps lock object -> reentrant lock + hold count for MONITORENTER/EXIT
    private static final ConcurrentHashMap<Object, MonitorState> monitorMap = new ConcurrentHashMap<>();

    /** O(1) opcode lookup table — maps opcode byte → Opcode. */
    private static final Opcode[] OPCODE_TABLE = buildOpcodeTable();
    /** Maps ordinal → Opcode (for dispatch table lookup). */
    private static final Opcode[] ORDINAL_TABLE = buildOrdinalTable();

    private static Opcode[] buildOpcodeTable() {
        Opcode[] all = Opcode.values();
        int max = 0;
        for (Opcode o : all) max = Math.max(max, o.code() & 0xFF);
        Opcode[] table = new Opcode[max + 1];
        for (Opcode o : all) table[o.code() & 0xFF] = o;
        return table;
    }

    private static Opcode[] buildOrdinalTable() {
        Opcode[] all = Opcode.values();
        int max = 0;
        for (Opcode o : all) max = Math.max(max, o.ordinal());
        Opcode[] table = new Opcode[max + 1];
        for (Opcode o : all) table[o.ordinal()] = o;
        return table;
    }

    /**
     * Randomized dispatch table: maps opcode byte → randomized block ID.
     * Generated at build time via {@link #initDispatchTable(long)}.
     * This makes every protected JAR have a unique control-flow structure.
     */
    private static final int[] DISPATCH = initDispatchTable(0);

    /** Seed-based dispatch randomization. Called from {@code <clinit>}. */
    public static void initDispatch(long seed) {
        if (seed != 0) {
            System.arraycopy(generateDispatchTable(seed), 0, DISPATCH, 0, 256);
        }
    }

    static int[] generateDispatchTable(long seed) {
        int[] table = new int[256];
        // Initialize all slots as junk (negative)
        java.util.Random rng = new java.util.Random(seed ^ 0xCAFEBABE);
        for (int i = 0; i < 256; i++) table[i] = -(1 + rng.nextInt(64));
        // Collect valid opcodes and shuffle their ordinals
        java.util.List<Integer> ordinals = new java.util.ArrayList<>();
        for (Opcode o : Opcode.values()) {
            if (o == Opcode.NOP) continue;
            ordinals.add(o.ordinal());
        }
        java.util.Collections.shuffle(ordinals, new java.util.Random(seed));
        // Assign: each valid opcode byte maps to a random ordinal
        // This means DISPATCH[opcodeByte] = randomOrdinal, creating a per-build
        // randomized mapping from opcode bytes to handler ordinals
        int idx = 0;
        for (Opcode o : Opcode.values()) {
            if (o == Opcode.NOP) continue;
            table[o.code() & 0xFF] = ordinals.get(idx++);
        }
        // NOP stays at 0 (identity)
        table[Opcode.NOP.code() & 0xFF] = Opcode.NOP.ordinal();
        return table;
    }

    static int[] initDispatchTable(long seed) {
        return seed != 0 ? generateDispatchTable(seed) : identityDispatch();
    }

    private static int[] identityDispatch() {
        int[] t = new int[256];
        for (Opcode o : Opcode.values()) {
            t[o.code() & 0xFF] = o.ordinal();
        }
        return t;
    }

    /** Set to true to enable instruction tracing to System.err. */
    public static boolean TRACE = false;

    // --- Thread-local varint position (avoids shared mutable state) ---
    private static final ThreadLocal<int[]> consumedTL = ThreadLocal.withInitial(() -> new int[1]);

    private VMInterpreter() {}

    /** Reentrant monitor state for MONITORENTER/EXIT. */
    private static final class MonitorState {
        final ReentrantLock lock = new ReentrantLock();
        int count;
    }

    /**
     * Decrypt an XOR-encrypted program blob from Base64-encoded strings.
     * Compact {@code <clinit>} call: {@code decrypt(b64data, b64key)}.
     */
    public static byte[] decrypt(String encodedData, String encodedKey) {
        byte[] encrypted = java.util.Base64.getDecoder().decode(encodedData);
        byte[] key = java.util.Base64.getDecoder().decode(encodedKey);
        int klen = key.length;
        for (int i = 0; i < encrypted.length; i++) {
            encrypted[i] ^= key[i % klen];
        }
        return encrypted;
    }

    /**
     * Decrypt an XOR-encrypted UTF-8 string.
     * Called from {@code <clinit>} to decrypt string constants.
     */
    public static String decryptString(byte[] encrypted, byte[] key) {
        byte[] dec = new byte[encrypted.length];
        int klen = key.length;
        for (int i = 0; i < encrypted.length; i++) {
            dec[i] = (byte) (encrypted[i] ^ key[i % klen]);
        }
        return new String(dec, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Execute a virtualized method.
     *
     * Program format: [exception_handler_count varint] [handler*] [instructions...]
     * Each handler: [start_pc varint] [end_pc varint] [handler_pc varint] [type_const_idx varint]
     * type_const_idx of -1 means "finally" (catches all exceptions).
     */
    public static Object execute(byte[] program, Object[] constants, Object[] args) {
        java.util.LinkedList<Object> rawStack = new java.util.LinkedList<>();
        Deque<Object> stack = rawStack;
        Object[] locals = new Object[256];

        if (args != null) {
            System.arraycopy(args, 0, locals, 0, args.length);
        }

        // Parse exception handler header
        int pc = 0;
        long headerInfo = readVarint(program, pc);
        int handlerCount = (int) headerInfo;
        pc = consumedTL.get()[0];

        int[][] handlers = new int[handlerCount][4];
        for (int h = 0; h < handlerCount; h++) {
            for (int f = 0; f < 4; f++) {
                handlers[h][f] = (int) readVarint(program, pc);
                pc = consumedTL.get()[0];
            }
        }

        // Parse shuffle flag and optional reverse mapping
        long shuffleFlag = readVarint(program, pc);
        pc = consumedTL.get()[0];
        byte[] reverseMap = null;
        if (shuffleFlag == 1) {
            reverseMap = new byte[256];
            for (int i = 0; i < 256; i++) {
                reverseMap[i] = program[pc++];
            }
        }

        // Main execution loop with exception handling per iteration
        int savedPc = pc;
        while (pc < program.length) {
            savedPc = pc;
            try {
            int rawByte = program[pc++] & 0xFF;
            // Layer 1: per-program shuffle (reverseMap in header)
            byte origByte = reverseMap != null ? reverseMap[rawByte] : (byte) rawByte;
            // Layer 2: per-build VM dispatch randomization (DISPATCH table)
            int dispatchIdx = DISPATCH[origByte & 0xFF];
            if (dispatchIdx < 0) {
                throw new IllegalArgumentException(
                    "Invalid opcode 0x" + Integer.toHexString(rawByte) + " at pc=" + (pc - 1));
            }
            Opcode op = dispatchIdx < ORDINAL_TABLE.length ? ORDINAL_TABLE[dispatchIdx] : null;

            if (TRACE) {
                System.err.printf("[pc=%d] %s  stack=%s%n", pc - 1, op, stack);
            }

            switch (op) {
                // --- Constants ---
                case ICONST: {
                    int value = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    stack.push(value);
                    break;
                }
                case LCONST: {
                    long value = readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    stack.push(value);
                    break;
                }
                case FCONST: {
                    int bits = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    stack.push(Float.intBitsToFloat(bits));
                    break;
                }
                case DCONST: {
                    long bits = readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    stack.push(Double.longBitsToDouble(bits));
                    break;
                }
                case LDC: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    stack.push(constants[idx]);
                    break;
                }

                // --- Local variable access ---
                case ILOAD: case LLOAD: case FLOAD: case DLOAD: case ALOAD: {
                    int slot = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    stack.push(locals[slot]);
                    break;
                }
                case ISTORE: case LSTORE: case FSTORE: case DSTORE: case ASTORE: {
                    int slot = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    locals[slot] = stack.pop();
                    break;
                }

                // --- Stack manipulation ---
                case DUP:
                    stack.push(stack.peek());
                    break;
                case DUP_X1: {
                    Object v1 = stack.pop();
                    Object v2 = stack.pop();
                    stack.push(v1);
                    stack.push(v2);
                    stack.push(v1);
                    break;
                }
                case DUP_X2: {
                    Object v1 = stack.pop();
                    Object v2 = stack.pop();
                    Object v3 = stack.pop();
                    stack.push(v1);
                    stack.push(v3);
                    stack.push(v2);
                    stack.push(v1);
                    break;
                }
                case DUP2: {
                    Object v1 = stack.pop();
                    Object v2 = stack.pop();
                    stack.push(v2);
                    stack.push(v1);
                    stack.push(v2);
                    stack.push(v1);
                    break;
                }
                case DUP2_X1: {
                    Object v1 = stack.pop();
                    Object v2 = stack.pop();
                    Object v3 = stack.pop();
                    stack.push(v2);
                    stack.push(v1);
                    stack.push(v3);
                    stack.push(v2);
                    stack.push(v1);
                    break;
                }
                case DUP2_X2: {
                    Object v1 = stack.pop();
                    Object v2 = stack.pop();
                    Object v3 = stack.pop();
                    Object v4 = stack.pop();
                    stack.push(v2);
                    stack.push(v1);
                    stack.push(v4);
                    stack.push(v3);
                    stack.push(v2);
                    stack.push(v1);
                    break;
                }
                case POP:
                    stack.pop();
                    break;
                case POP2:
                    stack.pop();
                    stack.pop();
                    break;
                case SWAP: {
                    Object a = stack.pop();
                    Object b = stack.pop();
                    stack.push(a);
                    stack.push(b);
                    break;
                }

                // --- Integer arithmetic ---
                case IADD: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a + b); break; }
                case ISUB: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a - b); break; }
                case IMUL: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a * b); break; }
                case IDIV: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a / b); break; }
                case IREM: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a % b); break; }
                case INEG: stack.push(-unboxInt(stack.pop())); break;

                // --- Long arithmetic ---
                case LADD: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a + b); break; }
                case LSUB: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a - b); break; }
                case LMUL: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a * b); break; }
                case LDIV: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a / b); break; }
                case LREM: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a % b); break; }
                case LNEG: stack.push(-(Long) stack.pop()); break;

                // --- Integer bitwise ---
                case IAND: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a & b); break; }
                case IOR:  { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a | b); break; }
                case IXOR: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a ^ b); break; }
                case ISHL: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a << b); break; }
                case ISHR: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a >> b); break; }
                case IUSHR:{ int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(a >>> b); break; }

                // --- Long bitwise ---
                case LAND: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a & b); break; }
                case LOR:  { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a | b); break; }
                case LXOR: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(a ^ b); break; }
                case LSHL: { long b = ((Number) stack.pop()).longValue(); long a = (Long) stack.pop(); stack.push(a << b); break; }
                case LSHR: { long b = ((Number) stack.pop()).longValue(); long a = (Long) stack.pop(); stack.push(a >> b); break; }
                case LUSHR:{ long b = ((Number) stack.pop()).longValue(); long a = (Long) stack.pop(); stack.push(a >>> b); break; }

                // --- Float arithmetic ---
                case FADD: { float b = (Float) stack.pop(); float a = (Float) stack.pop(); stack.push(a + b); break; }
                case FSUB: { float b = (Float) stack.pop(); float a = (Float) stack.pop(); stack.push(a - b); break; }
                case FMUL: { float b = (Float) stack.pop(); float a = (Float) stack.pop(); stack.push(a * b); break; }
                case FDIV: { float b = (Float) stack.pop(); float a = (Float) stack.pop(); stack.push(a / b); break; }
                case FREM: { float b = (Float) stack.pop(); float a = (Float) stack.pop(); stack.push(a % b); break; }
                case FNEG: stack.push(-(Float) stack.pop()); break;

                // --- Double arithmetic ---
                case DADD: { double b = (Double) stack.pop(); double a = (Double) stack.pop(); stack.push(a + b); break; }
                case DSUB: { double b = (Double) stack.pop(); double a = (Double) stack.pop(); stack.push(a - b); break; }
                case DMUL: { double b = (Double) stack.pop(); double a = (Double) stack.pop(); stack.push(a * b); break; }
                case DDIV: { double b = (Double) stack.pop(); double a = (Double) stack.pop(); stack.push(a / b); break; }
                case DREM: { double b = (Double) stack.pop(); double a = (Double) stack.pop(); stack.push(a % b); break; }
                case DNEG: stack.push(-(Double) stack.pop()); break;

                // --- Comparisons ---
                case ICMP: { int b = unboxInt(stack.pop()); int a = unboxInt(stack.pop()); stack.push(Integer.compare(a, b)); break; }
                case LCMP: { long b = (Long) stack.pop(); long a = (Long) stack.pop(); stack.push(Long.compare(a, b)); break; }
                case FCMPG: { float b = (Float) stack.pop(); float a = (Float) stack.pop(); stack.push(fcmpg(a, b)); break; }
                case FCMPL: { float b = (Float) stack.pop(); float a = (Float) stack.pop(); stack.push(fcmpl(a, b)); break; }
                case DCMPG: { double b = (Double) stack.pop(); double a = (Double) stack.pop(); stack.push(dcmpg(a, b)); break; }
                case DCMPL: { double b = (Double) stack.pop(); double a = (Double) stack.pop(); stack.push(dcmpl(a, b)); break; }

                // --- Branches ---
                case GOTO: {
                    // GOTO always jumps; the varint is the target offset, no fall-through
                    int target = (int) readVarint(program, pc);
                    pc = target;
                    break;
                }
                case IFEQ: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    if (unboxInt(stack.pop()) == 0) pc = target; break;
                }
                case IFNE: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    if (unboxInt(stack.pop()) != 0) pc = target; break;
                }
                case IFLT: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    if (unboxInt(stack.pop()) < 0) pc = target; break;
                }
                case IFGE: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    if (unboxInt(stack.pop()) >= 0) pc = target; break;
                }
                case IFGT: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    if (unboxInt(stack.pop()) > 0) pc = target; break;
                }
                case IFLE: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    if (unboxInt(stack.pop()) <= 0) pc = target; break;
                }
                case IF_ICMPEQ: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    int v2 = unboxInt(stack.pop()); int v1 = unboxInt(stack.pop());
                    if (v1 == v2) pc = target; break;
                }
                case IF_ICMPNE: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    int v2 = unboxInt(stack.pop()); int v1 = unboxInt(stack.pop());
                    if (v1 != v2) pc = target; break;
                }
                case IF_ICMPLT: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    int v2 = unboxInt(stack.pop()); int v1 = unboxInt(stack.pop());
                    if (v1 < v2) pc = target; break;
                }
                case IF_ICMPGE: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    int v2 = unboxInt(stack.pop()); int v1 = unboxInt(stack.pop());
                    if (v1 >= v2) pc = target; break;
                }
                case IF_ICMPGT: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    int v2 = unboxInt(stack.pop()); int v1 = unboxInt(stack.pop());
                    if (v1 > v2) pc = target; break;
                }
                case IF_ICMPLE: {
                    int target = (int) readVarint(program, pc); pc = consumedTL.get()[0];
                    int v2 = unboxInt(stack.pop()); int v1 = unboxInt(stack.pop());
                    if (v1 <= v2) pc = target; break;
                }
                case IF_ACMPEQ: {
                    int target = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    Object o2 = stack.pop();
                    Object o1 = stack.pop();
                    if (o1 == o2) pc = target;
                    break;
                }
                case IF_ACMPNE: {
                    int target = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    Object o2 = stack.pop();
                    Object o1 = stack.pop();
                    if (o1 != o2) pc = target;
                    break;
                }
                case IFNULL: {
                    int target = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    if (stack.pop() == null) pc = target;
                    break;
                }
                case IFNONNULL: {
                    int target = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    if (stack.pop() != null) pc = target;
                    break;
                }

                // --- Method invocation ---
                case INVOKESTATIC:
                case INVOKEVIRTUAL:
                case INVOKESPECIAL:
                case INVOKEINTERFACE: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    String[] desc = (String[]) constants[idx];
                    invokeMethod(op, desc, stack);
                    break;
                }

                // --- Field access ---
                case GETFIELD:
                case GETSTATIC: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    String[] desc = (String[]) constants[idx];
                    Object obj = (op == Opcode.GETFIELD) ? stack.pop() : null;
                    stack.push(getField(desc, obj));
                    break;
                }
                case PUTFIELD:
                case PUTSTATIC: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    String[] desc = (String[]) constants[idx];
                    Object value = stack.pop();
                    Object obj = (op == Opcode.PUTFIELD) ? stack.pop() : null;
                    putField(desc, obj, value);
                    break;
                }

                // --- Object creation ---
                case NEW: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    String className = (String) constants[idx];
                    stack.push(createObject(className));
                    break;
                }
                case NEWARRAY: {
                    int typeCode = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    int length = (Integer) stack.pop();
                    stack.push(createPrimitiveArray(typeCode, length));
                    break;
                }
                case ANEWARRAY: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    int length = unboxInt(stack.pop());
                    String className = (String) constants[idx];
                    stack.push(createObjectArray(className, length));
                    break;
                }
                case MULTIANEWARRAY: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    int dims = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    int[] sizes = new int[dims];
                    for (int d = dims - 1; d >= 0; d--) {
                        sizes[d] = unboxInt(stack.pop());
                    }
                    String className = (String) constants[idx];
                    stack.push(createMultiArray(className, sizes, 0));
                    break;
                }

                // --- Array access ---
                case IALOAD: case LALOAD: case FALOAD: case DALOAD:
                case AALOAD: case BALOAD: case CALOAD: case SALOAD: {
                    int index = (Integer) stack.pop();
                    Object array = stack.pop();
                    stack.push(Array.get(array, index));
                    break;
                }
                case IASTORE: case LASTORE: case FASTORE: case DASTORE:
                case AASTORE: case BASTORE: case CASTORE: case SASTORE: {
                    Object value = stack.pop();
                    int index = (Integer) stack.pop();
                    Object array = stack.pop();
                    Array.set(array, index, value);
                    break;
                }
                case ARRAYLENGTH: {
                    Object array = stack.pop();
                    stack.push(Array.getLength(array));
                    break;
                }

                // --- Primitive conversions ---
                case I2L: stack.push((long) unboxInt(stack.pop())); break;
                case I2F: stack.push((float) unboxInt(stack.pop())); break;
                case I2D: stack.push((double) unboxInt(stack.pop())); break;
                case L2I: stack.push((int) (long) (Long) stack.pop()); break;
                case L2F: stack.push((float) (long) (Long) stack.pop()); break;
                case L2D: stack.push((double) (long) (Long) stack.pop()); break;
                case F2I: stack.push((int) (float) (Float) stack.pop()); break;
                case F2L: stack.push((long) (float) (Float) stack.pop()); break;
                case F2D: stack.push((double) (float) (Float) stack.pop()); break;
                case D2I: stack.push((int) (double) (Double) stack.pop()); break;
                case D2L: stack.push((long) (double) (Double) stack.pop()); break;
                case D2F: stack.push((float) (double) (Double) stack.pop()); break;
                case I2B: stack.push((byte) unboxInt(stack.pop())); break;
                case I2C: stack.push((char) unboxInt(stack.pop())); break;
                case I2S: stack.push((short) unboxInt(stack.pop())); break;

                // --- Type checks ---
                case CHECKCAST: {
                    // operand: constant table index (class name) — skip the varint
                    pc = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    // At runtime, CHECKCAST is a no-op in our VM unless we want strict checking
                    // Just leave the object on the stack; JVM already verified it
                    break;
                }
                case INSTANCEOF: {
                    int idx = (int) readVarint(program, pc);
                    pc = consumedTL.get()[0];
                    String className = (String) constants[idx];
                    Object obj = stack.pop();
                    stack.push(instanceOf(obj, className));
                    break;
                }

                // --- Return ---
                case RETURN:
                    return null;
                case IRETURN:
                    return ((Integer) stack.pop());
                case LRETURN:
                    return ((Long) stack.pop());
                case FRETURN:
                    return ((Float) stack.pop());
                case DRETURN:
                    return ((Double) stack.pop());
                case ARETURN:
                    return stack.pop();

                case ATHROW: {
                    Object exc = stack.pop();
                    if (exc instanceof RuntimeException) throw (RuntimeException) exc;
                    if (exc instanceof Error) throw (Error) exc;
                    if (exc instanceof Throwable) throw new RuntimeException((Throwable) exc);
                    throw new RuntimeException("ATHROW with non-Throwable: " + exc);
                }

                // Synchronization — actual reentrant locking
                case MONITORENTER: {
                    Object lock = stack.pop();
                    MonitorState ms = monitorMap.computeIfAbsent(
                        System.identityHashCode(lock),
                        k -> new MonitorState());
                    ms.lock.lock();
                    ms.count++;
                    break;
                }
                case MONITOREXIT: {
                    Object lock = stack.pop();
                    MonitorState ms = monitorMap.get(System.identityHashCode(lock));
                    if (ms != null && ms.count > 0) {
                        ms.count--;
                        ms.lock.unlock();
                    }
                    break;
                }

                case NOP:
                    break;

                default:
                    throw new IllegalStateException(
                        "Unhandled opcode: " + op + " at pc=" + (pc - 1));
            }
            } catch (Throwable t) {
                // Find matching exception handler
                int handlerPc = findHandler(handlers, savedPc, t, constants);
                if (handlerPc < 0) {
                    if (t instanceof RuntimeException) throw (RuntimeException) t;
                    if (t instanceof Error) throw (Error) t;
                    throw new RuntimeException(t);
                }
                stack.clear();
                stack.push(t);
                pc = handlerPc;
            }
        }

        // Implicit return if program ends without RETURN
        return null;
    }

    /**
     * Find an exception handler matching the given throwable at the given PC.
     * Returns handler_pc, or -1 if no handler found.
     */
    private static int findHandler(int[][] handlers, int pc, Throwable t, Object[] constants) {
        for (int[] h : handlers) {
            int start = h[0], end = h[1], target = h[2], typeIdx = h[3];
            if (pc >= start && pc < end) {
                if (typeIdx == -1) return target; // finally — catches all
                // Check exception type
                String className = (String) constants[typeIdx];
                if (isInstanceOf(t, className)) return target;
            }
        }
        return -1;
    }

    /** Normalize boxed primitives to JVM conventions (boolean/char/short/byte → int). */
    private static Object normalizeBoxed(Object o) {
        if (o instanceof Boolean) return ((Boolean) o) ? 1 : 0;
        if (o instanceof Character) return (int) (Character) o;
        if (o instanceof Short) return (int) (Short) o;
        if (o instanceof Byte) return (int) (Byte) o;
        return o;
    }

    /** Unbox any Number (or Character) to int for arithmetic/comparisons. */
    private static int unboxInt(Object o) {
        if (o instanceof Integer) return (Integer) o;
        if (o instanceof Character) return (Character) o;
        if (o instanceof Short) return (Short) o;
        if (o instanceof Byte) return (Byte) o;
        if (o instanceof Number) return ((Number) o).intValue();
        throw new ClassCastException("Cannot convert " + o.getClass().getName() + " to int");
    }

    private static boolean isInstanceOf(Throwable t, String className) {
        String name = className.replace('/', '.');
        try {
            Class<?> c = Class.forName(name);
            return c.isInstance(t);
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    // --- Varint reading (used at runtime by the interpreter) ---

    // shared mutable result array to avoid allocation
    private static final int[] consumed = new int[1];

    private static long readVarint(byte[] data, int offset) {
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

        consumedTL.get()[0] = pos;
        return result;
    }

    // --- Reflective helpers ---

    // Method descriptor in constant table: String[] {"owner_class", "method_name", "descriptor"}
    private static void invokeMethod(Opcode op, String[] desc, Deque<Object> stack) {
        String key = desc[0] + "." + desc[1] + desc[2];
        try {
            int paramCount = countParams(desc[2]);
            Object[] args = new Object[paramCount];
            for (int i = paramCount - 1; i >= 0; i--) args[i] = stack.pop();
            Object target = null;
            if (op == Opcode.INVOKEVIRTUAL || op == Opcode.INVOKESPECIAL || op == Opcode.INVOKEINTERFACE)
                target = stack.pop();

            if (desc[1].equals("<init>")) {
                Constructor<?> ctor = ctorCache.computeIfAbsent(key, k -> {
                    try {
                        Class<?> o = Class.forName(desc[0].replace('/', '.'));
                        return findConstructor(o, desc[2]);
                    } catch (Exception e) { throw new RuntimeException("Ctor not found: " + key, e); }
                });
                Object result = ctor.newInstance(args);
                stack.push(result);
            } else {
                Method method = methodCache.computeIfAbsent(key, k -> {
                    try {
                        Class<?> o = Class.forName(desc[0].replace('/', '.'));
                        return findMethod(o, desc[1], desc[2]);
                    } catch (Exception e) { throw new RuntimeException("Method not found: " + key, e); }
                });
                Object result = method.invoke(target, args);
                if (!method.getReturnType().equals(void.class)) {
                    result = normalizeBoxed(result);
                    stack.push(result);
                }
            }
        } catch (Exception e) { throw new RuntimeException("Error invoking " + key, e); }
    }

    private static java.lang.reflect.Constructor<?> findConstructor(Class<?> o, String desc) {
        for (java.lang.reflect.Constructor<?> co : o.getDeclaredConstructors()) {
            if (getConstructorDescriptor(co).equals(desc)) { co.setAccessible(true); return co; }
        }
        throw new NoSuchMethodError(o.getName() + ".<init>" + desc);
    }
    private static String getConstructorDescriptor(java.lang.reflect.Constructor<?> co) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> p : co.getParameterTypes()) sb.append(classToDescriptor(p));
        sb.append(")V");
        return sb.toString();
    }



    private static Method findMethod(Class<?> owner, String name, String descriptor) {
        for (Method m : owner.getDeclaredMethods()) {
            if (m.getName().equals(name) && getMethodDescriptor(m).equals(descriptor)) {
                m.setAccessible(true);
                return m;
            }
        }
        // Also search superclass
        if (owner.getSuperclass() != null) {
            return findMethod(owner.getSuperclass(), name, descriptor);
        }
        throw new NoSuchMethodError(owner.getName() + "." + name + descriptor);
    }

    private static String getMethodDescriptor(Method m) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> p : m.getParameterTypes()) {
            sb.append(classToDescriptor(p));
        }
        sb.append(')');
        sb.append(classToDescriptor(m.getReturnType()));
        return sb.toString();
    }

    private static String classToDescriptor(Class<?> c) {
        if (c == void.class) return "V";
        if (c == int.class) return "I";
        if (c == long.class) return "J";
        if (c == float.class) return "F";
        if (c == double.class) return "D";
        if (c == boolean.class) return "Z";
        if (c == byte.class) return "B";
        if (c == char.class) return "C";
        if (c == short.class) return "S";
        if (c.isArray()) return c.getName().replace('.', '/');
        return "L" + c.getName().replace('.', '/') + ";";
    }

    private static int countParams(String descriptor) {
        int count = 0;
        int i = 1; // skip '('
        while (descriptor.charAt(i) != ')') {
            if (descriptor.charAt(i) == 'L') {
                i = descriptor.indexOf(';', i) + 1;
            } else if (descriptor.charAt(i) == '[') {
                i++;
                while (descriptor.charAt(i) == '[') i++;
                if (descriptor.charAt(i) == 'L') i = descriptor.indexOf(';', i) + 1;
                else i++;
            } else {
                i++;
            }
            count++;
        }
        return count;
    }

    // Field descriptor: String[] {"owner_class", "field_name", "type_descriptor"}
    private static Object getField(String[] desc, Object obj) {
        String key = desc[0] + "." + desc[1];
        try {
            Field field = fieldCache.computeIfAbsent(key, k -> {
                try {
                    Class<?> owner = Class.forName(desc[0].replace('/', '.'));
                    Field f = owner.getDeclaredField(desc[1]);
                    f.setAccessible(true);
                    return f;
                } catch (Exception e) {
                    throw new RuntimeException("Field not found: " + key, e);
                }
            });
            return field.get(obj);
        } catch (Exception e) {
            throw new RuntimeException("Error reading field " + key, e);
        }
    }

    private static void putField(String[] desc, Object obj, Object value) {
        String key = desc[0] + "." + desc[1];
        try {
            Field field = fieldCache.computeIfAbsent(key, k -> {
                try {
                    Class<?> owner = Class.forName(desc[0].replace('/', '.'));
                    Field f = owner.getDeclaredField(desc[1]);
                    f.setAccessible(true);
                    return f;
                } catch (Exception e) {
                    throw new RuntimeException("Field not found: " + key, e);
                }
            });
            field.set(obj, value);
        } catch (Exception e) {
            throw new RuntimeException("Error writing field " + key, e);
        }
    }

    private static Object createObject(String className) {
        String name = className.replace('/', '.');
        try {
            Constructor<?> ctor = ctorCache.computeIfAbsent(name, k -> {
                try {
                    Class<?> c = Class.forName(name);
                    Constructor<?> ct = c.getDeclaredConstructor();
                    ct.setAccessible(true);
                    return ct;
                } catch (Exception e) {
                    throw new RuntimeException("No default constructor: " + name, e);
                }
            });
            return ctor.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Error creating instance of " + name, e);
        }
    }

    private static Object createPrimitiveArray(int typeCode, int length) {
        switch (typeCode) {
            case 4:  return new boolean[length];
            case 5:  return new char[length];
            case 6:  return new float[length];
            case 7:  return new double[length];
            case 8:  return new byte[length];
            case 9:  return new short[length];
            case 10: return new int[length];
            case 11: return new long[length];
            default: throw new IllegalArgumentException("Unknown array type code: " + typeCode);
        }
    }

    private static Object createMultiArray(String className, int[] sizes, int dim) {
        if (dim >= sizes.length) return null;
        int length = sizes[dim];
        if (className.startsWith("[")) {
            // Array type — use component type
            String componentName = className.substring(1);
            try {
                Class<?> compType = classForName(componentName.replace('/', '.'));
                Object arr = Array.newInstance(compType, length);
                if (dim + 1 < sizes.length) {
                    for (int i = 0; i < length; i++) {
                        Array.set(arr, i, createMultiArray(componentName, sizes, dim + 1));
                    }
                }
                return arr;
            } catch (Exception e) {
                throw new RuntimeException("Error creating multi-array: " + className, e);
            }
        } else {
            // Object type
            try {
                String name = className.replace('/', '.');
                Class<?> compType = classForName(name);
                Object arr = Array.newInstance(compType, length);
                return arr;
            } catch (Exception e) {
                throw new RuntimeException("Error creating array of " + className, e);
            }
        }
    }

    private static Object createObjectArray(String className, int length) {
        try {
            String name = className.replace('/', '.');
            Class<?> componentType = classForName(name);
            return Array.newInstance(componentType, length);
        } catch (Exception e) {
            throw new RuntimeException("Error creating array of " + className, e);
        }
    }

    private static boolean instanceOf(Object obj, String className) {
        if (obj == null) return false;
        try {
            String name = className.replace('/', '.');
            Class<?> c = classForName(name);
            return c.isInstance(obj);
        } catch (Exception e) {
            return false;
        }
    }

    private static Class<?> classForName(String name) throws ClassNotFoundException {
        switch (name) {
            case "boolean": return boolean.class;
            case "char":    return char.class;
            case "float":   return float.class;
            case "double":  return double.class;
            case "byte":    return byte.class;
            case "short":   return short.class;
            case "int":     return int.class;
            case "long":    return long.class;
            default:        return Class.forName(name);
        }
    }

    // --- Float/double comparison helpers (match JVM semantics) ---

    private static int fcmpg(float a, float b) {
        if (Float.isNaN(a) || Float.isNaN(b)) return 1;
        return Float.compare(a, b);
    }

    private static int fcmpl(float a, float b) {
        if (Float.isNaN(a) || Float.isNaN(b)) return -1;
        return Float.compare(a, b);
    }

    private static int dcmpg(double a, double b) {
        if (Double.isNaN(a) || Double.isNaN(b)) return 1;
        return Double.compare(a, b);
    }

    private static int dcmpl(double a, double b) {
        if (Double.isNaN(a) || Double.isNaN(b)) return -1;
        return Double.compare(a, b);
    }
}
