package opaddon.isa;

import java.util.Arrays;
import java.util.Objects;

/**
 * A single instruction in the custom ISA: an opcode plus its operands.
 *
 * Operands are stored as long values (wide enough for int indices,
 * long/double constants, and branch offsets). The Encoder converts them
 * to/from signed LEB128 varints in the binary stream.
 */
public final class Instruction {

    private final Opcode opcode;
    private final long[] operands;

    public Instruction(Opcode opcode, long... operands) {
        this.opcode = Objects.requireNonNull(opcode);
        this.operands = operands.clone();
    }

    public Opcode opcode() {
        return opcode;
    }

    public long[] operands() {
        return operands.clone();
    }

    public long operand(int index) {
        return operands[index];
    }

    public int operandCount() {
        return operands.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Instruction that)) return false;
        return opcode == that.opcode && Arrays.equals(operands, that.operands);
    }

    @Override
    public int hashCode() {
        return Objects.hash(opcode, Arrays.hashCode(operands));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(opcode.name());
        if (operands.length > 0) {
            sb.append(' ');
            for (int i = 0; i < operands.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append(operands[i]);
            }
        }
        return sb.toString();
    }

    // --- Convenience factories ---

    public static Instruction iconst(int value) { return new Instruction(Opcode.ICONST, value); }
    public static Instruction lconst(long value) { return new Instruction(Opcode.LCONST, value); }
    public static Instruction fconst(float value) { return new Instruction(Opcode.FCONST, Float.floatToRawIntBits(value)); }
    public static Instruction dconst(double value) { return new Instruction(Opcode.DCONST, Double.doubleToRawLongBits(value)); }
    public static Instruction ldc(int index) { return new Instruction(Opcode.LDC, index); }
    public static Instruction iload(int slot) { return new Instruction(Opcode.ILOAD, slot); }
    public static Instruction lload(int slot) { return new Instruction(Opcode.LLOAD, slot); }
    public static Instruction fload(int slot) { return new Instruction(Opcode.FLOAD, slot); }
    public static Instruction dload(int slot) { return new Instruction(Opcode.DLOAD, slot); }
    public static Instruction aload(int slot) { return new Instruction(Opcode.ALOAD, slot); }
    public static Instruction istore(int slot) { return new Instruction(Opcode.ISTORE, slot); }
    public static Instruction lstore(int slot) { return new Instruction(Opcode.LSTORE, slot); }
    public static Instruction fstore(int slot) { return new Instruction(Opcode.FSTORE, slot); }
    public static Instruction dstore(int slot) { return new Instruction(Opcode.DSTORE, slot); }
    public static Instruction astore(int slot) { return new Instruction(Opcode.ASTORE, slot); }
    public static Instruction dup() { return new Instruction(Opcode.DUP); }
    public static Instruction pop() { return new Instruction(Opcode.POP); }
    public static Instruction swap() { return new Instruction(Opcode.SWAP); }
    public static Instruction dup_x1() { return new Instruction(Opcode.DUP_X1); }
    public static Instruction dup_x2() { return new Instruction(Opcode.DUP_X2); }
    public static Instruction dup2() { return new Instruction(Opcode.DUP2); }
    public static Instruction dup2_x1() { return new Instruction(Opcode.DUP2_X1); }
    public static Instruction dup2_x2() { return new Instruction(Opcode.DUP2_X2); }
    public static Instruction pop2() { return new Instruction(Opcode.POP2); }

    // Arithmetic
    public static Instruction iadd() { return new Instruction(Opcode.IADD); }
    public static Instruction isub() { return new Instruction(Opcode.ISUB); }
    public static Instruction imul() { return new Instruction(Opcode.IMUL); }
    public static Instruction idiv() { return new Instruction(Opcode.IDIV); }
    public static Instruction irem() { return new Instruction(Opcode.IREM); }
    public static Instruction ineg() { return new Instruction(Opcode.INEG); }
    public static Instruction ladd() { return new Instruction(Opcode.LADD); }
    public static Instruction lsub() { return new Instruction(Opcode.LSUB); }
    public static Instruction lmul() { return new Instruction(Opcode.LMUL); }
    public static Instruction ldiv() { return new Instruction(Opcode.LDIV); }
    public static Instruction lrem() { return new Instruction(Opcode.LREM); }
    public static Instruction lneg() { return new Instruction(Opcode.LNEG); }
    // Integer bitwise
    public static Instruction iand() { return new Instruction(Opcode.IAND); }
    public static Instruction ior()  { return new Instruction(Opcode.IOR); }
    public static Instruction ixor() { return new Instruction(Opcode.IXOR); }
    public static Instruction ishl() { return new Instruction(Opcode.ISHL); }
    public static Instruction ishr() { return new Instruction(Opcode.ISHR); }
    public static Instruction iushr(){ return new Instruction(Opcode.IUSHR); }
    // Long bitwise
    public static Instruction land() { return new Instruction(Opcode.LAND); }
    public static Instruction lor()  { return new Instruction(Opcode.LOR); }
    public static Instruction lxor() { return new Instruction(Opcode.LXOR); }
    public static Instruction lshl() { return new Instruction(Opcode.LSHL); }
    public static Instruction lshr() { return new Instruction(Opcode.LSHR); }
    public static Instruction lushr(){ return new Instruction(Opcode.LUSHR); }
    public static Instruction fadd() { return new Instruction(Opcode.FADD); }
    public static Instruction fsub() { return new Instruction(Opcode.FSUB); }
    public static Instruction fmul() { return new Instruction(Opcode.FMUL); }
    public static Instruction fdiv() { return new Instruction(Opcode.FDIV); }
    public static Instruction frem() { return new Instruction(Opcode.FREM); }
    public static Instruction fneg() { return new Instruction(Opcode.FNEG); }
    public static Instruction dadd() { return new Instruction(Opcode.DADD); }
    public static Instruction dsub() { return new Instruction(Opcode.DSUB); }
    public static Instruction dmul() { return new Instruction(Opcode.DMUL); }
    public static Instruction ddiv() { return new Instruction(Opcode.DDIV); }
    public static Instruction drem() { return new Instruction(Opcode.DREM); }
    public static Instruction dneg() { return new Instruction(Opcode.DNEG); }

    // Comparisons
    public static Instruction icmp() { return new Instruction(Opcode.ICMP); }
    public static Instruction lcmp() { return new Instruction(Opcode.LCMP); }
    public static Instruction fcmpg() { return new Instruction(Opcode.FCMPG); }
    public static Instruction fcmpl() { return new Instruction(Opcode.FCMPL); }
    public static Instruction dcmpg() { return new Instruction(Opcode.DCMPG); }
    public static Instruction dcmpl() { return new Instruction(Opcode.DCMPL); }

    // Branches
    public static Instruction ifeq(int offset) { return new Instruction(Opcode.IFEQ, offset); }
    public static Instruction ifne(int offset) { return new Instruction(Opcode.IFNE, offset); }
    public static Instruction iflt(int offset) { return new Instruction(Opcode.IFLT, offset); }
    public static Instruction ifge(int offset) { return new Instruction(Opcode.IFGE, offset); }
    public static Instruction ifgt(int offset) { return new Instruction(Opcode.IFGT, offset); }
    public static Instruction ifle(int offset) { return new Instruction(Opcode.IFLE, offset); }
    public static Instruction if_icmpeq(int offset) { return new Instruction(Opcode.IF_ICMPEQ, offset); }
    public static Instruction if_icmpne(int offset) { return new Instruction(Opcode.IF_ICMPNE, offset); }
    public static Instruction if_icmplt(int offset) { return new Instruction(Opcode.IF_ICMPLT, offset); }
    public static Instruction if_icmpge(int offset) { return new Instruction(Opcode.IF_ICMPGE, offset); }
    public static Instruction if_icmpgt(int offset) { return new Instruction(Opcode.IF_ICMPGT, offset); }
    public static Instruction if_icmple(int offset) { return new Instruction(Opcode.IF_ICMPLE, offset); }
    public static Instruction if_acmpeq(int offset) { return new Instruction(Opcode.IF_ACMPEQ, offset); }
    public static Instruction if_acmpne(int offset) { return new Instruction(Opcode.IF_ACMPNE, offset); }
    public static Instruction ifnull(int offset) { return new Instruction(Opcode.IFNULL, offset); }
    public static Instruction ifnonnull(int offset) { return new Instruction(Opcode.IFNONNULL, offset); }
    public static Instruction goto_(int offset) { return new Instruction(Opcode.GOTO, offset); }

    // Method calls
    public static Instruction invokestatic(int idx) { return new Instruction(Opcode.INVOKESTATIC, idx); }
    public static Instruction invokevirtual(int idx) { return new Instruction(Opcode.INVOKEVIRTUAL, idx); }
    public static Instruction invokespecial(int idx) { return new Instruction(Opcode.INVOKESPECIAL, idx); }
    public static Instruction invokeinterface(int idx) { return new Instruction(Opcode.INVOKEINTERFACE, idx); }

    // Field access
    public static Instruction getfield(int idx) { return new Instruction(Opcode.GETFIELD, idx); }
    public static Instruction putfield(int idx) { return new Instruction(Opcode.PUTFIELD, idx); }
    public static Instruction getstatic(int idx) { return new Instruction(Opcode.GETSTATIC, idx); }
    public static Instruction putstatic(int idx) { return new Instruction(Opcode.PUTSTATIC, idx); }

    // Object creation
    public static Instruction new_(int idx) { return new Instruction(Opcode.NEW, idx); }
    public static Instruction newarray(int typeCode) { return new Instruction(Opcode.NEWARRAY, typeCode); }
    public static Instruction anewarray(int idx) { return new Instruction(Opcode.ANEWARRAY, idx); }
    public static Instruction multianewarray(int idx, int dims) { return new Instruction(Opcode.MULTIANEWARRAY, idx, dims); }

    // Array access
    public static Instruction iaload() { return new Instruction(Opcode.IALOAD); }
    public static Instruction laload() { return new Instruction(Opcode.LALOAD); }
    public static Instruction faload() { return new Instruction(Opcode.FALOAD); }
    public static Instruction daload() { return new Instruction(Opcode.DALOAD); }
    public static Instruction aaload() { return new Instruction(Opcode.AALOAD); }
    public static Instruction baload() { return new Instruction(Opcode.BALOAD); }
    public static Instruction caload() { return new Instruction(Opcode.CALOAD); }
    public static Instruction saload() { return new Instruction(Opcode.SALOAD); }
    public static Instruction iastore() { return new Instruction(Opcode.IASTORE); }
    public static Instruction lastore() { return new Instruction(Opcode.LASTORE); }
    public static Instruction fastore() { return new Instruction(Opcode.FASTORE); }
    public static Instruction dastore() { return new Instruction(Opcode.DASTORE); }
    public static Instruction aastore() { return new Instruction(Opcode.AASTORE); }
    public static Instruction bastore() { return new Instruction(Opcode.BASTORE); }
    public static Instruction castore() { return new Instruction(Opcode.CASTORE); }
    public static Instruction sastore() { return new Instruction(Opcode.SASTORE); }
    public static Instruction arraylength() { return new Instruction(Opcode.ARRAYLENGTH); }

    // Primitive conversions
    public static Instruction i2l() { return new Instruction(Opcode.I2L); }
    public static Instruction i2f() { return new Instruction(Opcode.I2F); }
    public static Instruction i2d() { return new Instruction(Opcode.I2D); }
    public static Instruction l2i() { return new Instruction(Opcode.L2I); }
    public static Instruction l2f() { return new Instruction(Opcode.L2F); }
    public static Instruction l2d() { return new Instruction(Opcode.L2D); }
    public static Instruction f2i() { return new Instruction(Opcode.F2I); }
    public static Instruction f2l() { return new Instruction(Opcode.F2L); }
    public static Instruction f2d() { return new Instruction(Opcode.F2D); }
    public static Instruction d2i() { return new Instruction(Opcode.D2I); }
    public static Instruction d2l() { return new Instruction(Opcode.D2L); }
    public static Instruction d2f() { return new Instruction(Opcode.D2F); }
    public static Instruction i2b() { return new Instruction(Opcode.I2B); }
    public static Instruction i2c() { return new Instruction(Opcode.I2C); }
    public static Instruction i2s() { return new Instruction(Opcode.I2S); }

    // Type checks
    public static Instruction checkcast(int idx) { return new Instruction(Opcode.CHECKCAST, idx); }
    public static Instruction instanceof_(int idx) { return new Instruction(Opcode.INSTANCEOF, idx); }

    // Return
    public static Instruction return_() { return new Instruction(Opcode.RETURN); }
    public static Instruction ireturn() { return new Instruction(Opcode.IRETURN); }
    public static Instruction lreturn() { return new Instruction(Opcode.LRETURN); }
    public static Instruction freturn() { return new Instruction(Opcode.FRETURN); }
    public static Instruction dreturn() { return new Instruction(Opcode.DRETURN); }
    public static Instruction areturn() { return new Instruction(Opcode.ARETURN); }

    public static Instruction athrow() { return new Instruction(Opcode.ATHROW); }
    public static Instruction monitorenter() { return new Instruction(Opcode.MONITORENTER); }
    public static Instruction monitorexit() { return new Instruction(Opcode.MONITOREXIT); }
    public static Instruction nop() { return new Instruction(Opcode.NOP); }
}
