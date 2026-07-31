package opaddon.isa;

/**
 * Custom stack-based ISA opcodes.
 *
 * Each opcode has a fixed 1-byte code. Operands follow as signed LEB128 varints.
 * The opcode-to-byte mapping can be shuffled per build (Phase 7 hardening).
 */
public enum Opcode {

    // --- Constants ---
    ICONST(0x01),
    LCONST(0x02),
    FCONST(0x03),
    DCONST(0x04),
    LDC(0x05),          // push from constant table by index

    // --- Local variable access ---
    ILOAD(0x10),
    LLOAD(0x11),
    FLOAD(0x12),
    DLOAD(0x13),
    ALOAD(0x14),
    ISTORE(0x15),
    LSTORE(0x16),
    FSTORE(0x17),
    DSTORE(0x18),
    ASTORE(0x19),

    // --- Stack manipulation ---
    DUP(0x20),
    POP(0x21),
    SWAP(0x22),
    DUP_X1(0x23),
    DUP_X2(0x24),
    DUP2(0x25),
    DUP2_X1(0x26),
    DUP2_X2(0x27),
    POP2(0x28),

    // --- Integer arithmetic ---
    IADD(0x30),
    ISUB(0x31),
    IMUL(0x32),
    IDIV(0x33),
    IREM(0x34),
    INEG(0x35),

    // --- Long arithmetic ---
    LADD(0x38),
    LSUB(0x39),
    LMUL(0x3A),
    LDIV(0x3B),
    LREM(0x3C),
    LNEG(0x3D),

    // --- Integer bitwise ---
    IAND(0x2A),
    IOR(0x2B),
    IXOR(0x2C),
    ISHL(0x2D),
    ISHR(0x2E),
    IUSHR(0x2F),

    // --- Long bitwise ---
    LAND(0x3E),
    LOR(0x3F),
    LXOR(0x46),
    LSHL(0x47),
    LSHR(0x4E),
    LUSHR(0x4F),

    // --- Float arithmetic ---
    FADD(0x40),
    FSUB(0x41),
    FMUL(0x42),
    FDIV(0x43),
    FREM(0x44),
    FNEG(0x45),

    // --- Double arithmetic ---
    DADD(0x48),
    DSUB(0x49),
    DMUL(0x4A),
    DDIV(0x4B),
    DREM(0x4C),
    DNEG(0x4D),

    // --- Integer comparisons ---
    ICMP(0x50),         // compare two ints, push -1/0/1
    LCMP(0x51),
    FCMPG(0x52),
    FCMPL(0x53),
    DCMPG(0x54),
    DCMPL(0x55),

    // --- Branches (operand: absolute byte offset in program) ---
    IFEQ(0x60),
    IFNE(0x61),
    IFLT(0x62),
    IFGE(0x63),
    IFGT(0x64),
    IFLE(0x65),
    IF_ICMPEQ(0x66),
    IF_ICMPNE(0x67),
    IF_ICMPLT(0x68),
    IF_ICMPGE(0x69),
    IF_ICMPGT(0x6A),
    IF_ICMPLE(0x6B),
    IF_ACMPEQ(0x6C),
    IF_ACMPNE(0x6D),
    IFNULL(0x6E),
    IFNONNULL(0x6F),
    GOTO(0x70),

    // --- Method invocation (operand: constant table index) ---
    INVOKESTATIC(0x80),
    INVOKEVIRTUAL(0x81),
    INVOKESPECIAL(0x82),
    INVOKEINTERFACE(0x83),

    // --- Field access (operand: constant table index) ---
    GETFIELD(0x84),
    PUTFIELD(0x85),
    GETSTATIC(0x86),
    PUTSTATIC(0x87),

    // --- Object creation ---
    NEW(0x90),          // operand: constant table index (class name)
    NEWARRAY(0x91),     // operand: type code (4=boolean,5=char,6=float,7=double,8=byte,9=short,10=int,11=long)
    ANEWARRAY(0x92),    // operand: constant table index (class name)
    MULTIANEWARRAY(0xA4), // operands: constant table index, dimensions count

    // --- Array access ---
    IALOAD(0x93),
    LALOAD(0x94),
    FALOAD(0x95),
    DALOAD(0x96),
    AALOAD(0x97),
    BALOAD(0x98),
    CALOAD(0x99),
    SALOAD(0x9A),
    IASTORE(0x9B),
    LASTORE(0x9C),
    FASTORE(0x9D),
    DASTORE(0x9E),
    AASTORE(0x9F),
    BASTORE(0xA0),
    CASTORE(0xA1),
    SASTORE(0xA2),
    ARRAYLENGTH(0xA3),

    // --- Primitive conversions ---
    I2L(0xB0), I2F(0xB1), I2D(0xB2),
    L2I(0xB3), L2F(0xB4), L2D(0xB5),
    F2I(0xB6), F2L(0xB7), F2D(0xB8),
    D2I(0xB9), D2L(0xBA), D2F(0xBB),
    I2B(0xBC), I2C(0xBD), I2S(0xBE),

    // --- Type checks (operand: constant table index) ---
    CHECKCAST(0xA8),
    INSTANCEOF(0xA9),

    // --- Return ---
    RETURN(0xF0),
    IRETURN(0xF1),
    LRETURN(0xF2),
    FRETURN(0xF3),
    DRETURN(0xF4),
    ARETURN(0xF5),

    // --- Exception ---
    ATHROW(0xF6),

    // --- Synchronization ---
    MONITORENTER(0xF7),
    MONITOREXIT(0xF8),

    // --- Special ---
    NOP(0x00),
    ;

    private final byte code;

    Opcode(int code) {
        this.code = (byte) code;
    }

    public byte code() {
        return code;
    }

    /**
     * Look up an opcode by its byte value.
     */
    public static Opcode fromCode(byte b) {
        for (Opcode op : values()) {
            if (op.code == b) return op;
        }
        throw new IllegalArgumentException("Unknown opcode byte: " + Integer.toHexString(b & 0xFF));
    }
}
