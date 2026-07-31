package opaddon.vm;

import opaddon.isa.Encoder;
import opaddon.isa.Instruction;
import opaddon.isa.Opcode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Helper that builds known custom ISA programs for interpreter testing.
 * Each method returns an encoded program + constants table pair.
 *
 * Branch instructions use their operand as the TARGET INSTRUCTION INDEX.
 * {@link #resolveBranches(List)} converts those indices to absolute byte offsets
 * and iterates until the offsets converge.
 */
public final class TestPrograms {

    private TestPrograms() {}

    public record Program(byte[] code, Object[] constants) {}

    /**
     * int add(int a, int b) { return a + b; }
     */
    public static Program intAdd() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));
        insns.add(Instruction.iload(1));
        insns.add(Instruction.iadd());
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program intMultiply() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));
        insns.add(Instruction.iload(1));
        insns.add(Instruction.imul());
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program intComplex() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));
        insns.add(Instruction.iload(1));
        insns.add(Instruction.imul());
        insns.add(Instruction.iload(2));
        insns.add(Instruction.iadd());
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program intNegate() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));
        insns.add(Instruction.ineg());
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program intDivide() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));
        insns.add(Instruction.iload(1));
        insns.add(Instruction.idiv());
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program intRemainder() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));
        insns.add(Instruction.iload(1));
        insns.add(Instruction.irem());
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program longAdd() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.lload(0));
        insns.add(Instruction.lload(1));
        insns.add(Instruction.ladd());
        insns.add(Instruction.lreturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program floatAdd() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.fload(0));
        insns.add(Instruction.fload(1));
        insns.add(Instruction.fadd());
        insns.add(Instruction.freturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program doubleAdd() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.dload(0));
        insns.add(Instruction.dload(1));
        insns.add(Instruction.dadd());
        insns.add(Instruction.dreturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    /**
     * int max(int a, int b) { return a > b ? a : b; }
     *
     * Instructions:
     *   0: ILOAD 0
     *   1: ILOAD 1
     *   2: IF_ICMPGT -> 5     (if a > b, jump to "return a")
     *   3: ILOAD 1            (else: return b)
     *   4: GOTO -> 6          (skip then-branch)
     *   5: ILOAD 0            (then: return a)
     *   6: IRETURN
     */
    public static Program intMax() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));       // 0
        insns.add(Instruction.iload(1));       // 1
        insns.add(Instruction.if_icmpgt(5));   // 2: if a>b goto "return a"
        insns.add(Instruction.iload(1));       // 3: return b
        insns.add(Instruction.goto_(6));       // 4: goto ireturn
        insns.add(Instruction.iload(0));       // 5: return a
        insns.add(Instruction.ireturn());      // 6
        resolveBranches(insns);
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    /**
     * int abs(int x) { return x >= 0 ? x : -x; }
     *
     *   0: ILOAD 0
     *   1: IFGE -> 5          (if x>=0, skip the negate path)
     *   2: ILOAD 0            (negate path)
     *   3: INEG
     *   4: IRETURN
     *   5: ILOAD 0            (skip label: non-negative path)
     *   6: IRETURN
     */
    public static Program intAbs() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iload(0));       // 0
        insns.add(Instruction.ifge(5));        // 1: if x>=0 jump to skip
        insns.add(Instruction.iload(0));       // 2: negate path
        insns.add(Instruction.ineg());         // 3
        insns.add(Instruction.ireturn());      // 4
        insns.add(Instruction.iload(0));       // 5: skip label
        insns.add(Instruction.ireturn());      // 6
        resolveBranches(insns);
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    /**
     * int sumToN(int n) { int s = 0; for (int i = 1; i <= n; i++) s += i; return s; }
     *
     *   0:  ICONST 0
     *   1:  ISTORE 1           (s = 0)
     *   2:  ICONST 1
     *   3:  ISTORE 2           (i = 1)
     *   4:  ILOAD 2            (loop:)
     *   5:  ILOAD 0
     *   6:  IF_ICMPGT -> 18    (if i > n goto end)
     *   7:  ILOAD 1
     *   8:  ILOAD 2
     *   9:  IADD
     *   10: ISTORE 1           (s += i)
     *   11: ILOAD 2
     *   12: ICONST 1
     *   13: IADD
     *   14: ISTORE 2           (i++)
     *   15: GOTO -> 4          (goto loop)
     *   16: ILOAD 1            (end:)
     *   17: IRETURN
     */
    public static Program sumToN() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iconst(0));      // 0
        insns.add(Instruction.istore(1));      // 1: s = 0
        insns.add(Instruction.iconst(1));      // 2
        insns.add(Instruction.istore(2));      // 3: i = 1
        insns.add(Instruction.iload(2));       // 4: loop:
        insns.add(Instruction.iload(0));       // 5
        insns.add(Instruction.if_icmpgt(16));  // 6: if i > n goto end
        insns.add(Instruction.iload(1));       // 7
        insns.add(Instruction.iload(2));       // 8
        insns.add(Instruction.iadd());         // 9
        insns.add(Instruction.istore(1));      // 10: s += i
        insns.add(Instruction.iload(2));       // 11
        insns.add(Instruction.iconst(1));      // 12
        insns.add(Instruction.iadd());         // 13
        insns.add(Instruction.istore(2));      // 14: i++
        insns.add(Instruction.goto_(4));       // 15: goto loop
        insns.add(Instruction.iload(1));       // 16: end:
        insns.add(Instruction.ireturn());      // 17
        resolveBranches(insns);
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    /**
     * Iterative factorial: int r=1; while(n>1){r*=n; n--;} return r;
     *
     *   0:  ICONST 1
     *   1:  ISTORE 1           (r = 1)
     *   2:  ILOAD 0            (loop:)
     *   3:  ICONST 1
     *   4:  IF_ICMPLE -> 16    (if n <= 1 goto end)
     *   5:  ILOAD 1
     *   6:  ILOAD 0
     *   7:  IMUL
     *   8:  ISTORE 1           (r *= n)
     *   9:  ILOAD 0
     *   10: ICONST 1
     *   11: ISUB
     *   12: ISTORE 0           (n--)
     *   13: GOTO -> 2          (goto loop)
     *   14: ILOAD 1            (end:)
     *   15: IRETURN
     */
    public static Program factorial() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iconst(1));      // 0
        insns.add(Instruction.istore(1));      // 1: r = 1
        insns.add(Instruction.iload(0));       // 2: loop:
        insns.add(Instruction.iconst(1));      // 3
        insns.add(Instruction.if_icmple(14));  // 4: if n <= 1 goto end
        insns.add(Instruction.iload(1));       // 5
        insns.add(Instruction.iload(0));       // 6
        insns.add(Instruction.imul());         // 7
        insns.add(Instruction.istore(1));      // 8: r *= n
        insns.add(Instruction.iload(0));       // 9
        insns.add(Instruction.iconst(1));      // 10
        insns.add(Instruction.isub());         // 11
        insns.add(Instruction.istore(0));      // 12: n--
        insns.add(Instruction.goto_(2));       // 13: goto loop
        insns.add(Instruction.iload(1));       // 14: end:
        insns.add(Instruction.ireturn());      // 15
        resolveBranches(insns);
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program constantReturn() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.iconst(42));
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program voidNoop() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.return_());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[0]);
    }

    public static Program stringLdc() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.ldc(0));  // "hello"
        insns.add(Instruction.areturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[]{"hello"});
    }

    public static Program constantLdc() {
        List<Instruction> insns = new ArrayList<>();
        insns.add(Instruction.ldc(0));  // 12345
        insns.add(Instruction.ireturn());
        return new Program(Encoder.encodeWithHeader(insns, new int[0][]), new Object[]{12345});
    }

    // --- Branch resolution ---

    /**
     * Resolves branch targets by computing instruction byte offsets
     * and patching branch operands from target-instruction-index to absolute byte offset.
     *
     * Uses a two-pass approach: first record branch target indices,
     * then compute offsets and patch in a single pass.
     */
    private static void resolveBranches(List<Instruction> insns) {
        // Record: branch instruction index -> target instruction index
        Map<Integer, Integer> branchTargets = new HashMap<>();
        for (int i = 0; i < insns.size(); i++) {
            Instruction insn = insns.get(i);
            if (isBranch(insn.opcode())) {
                branchTargets.put(i, (int) insn.operand(0));
            }
        }

        // Compute byte offsets using CURRENT (unpatched) branch operands
        int[] offsets = computeOffsets(insns);

        // Account for exception handler header
        // varint(handlerCount=0) + varint(shuffleFlag=0) = 2 bytes
        int headerSize = 2;

        // Patch each branch with the resolved byte offset + header offset
        for (Map.Entry<Integer, Integer> entry : branchTargets.entrySet()) {
            int branchIdx = entry.getKey();
            int targetIdx = entry.getValue();
            Instruction old = insns.get(branchIdx);
            insns.set(branchIdx, new Instruction(old.opcode(), offsets[targetIdx] + headerSize));
        }
    }

    /**
     * Compute the byte offset of each instruction assuming all operands
     * use their current values for varint sizing.
     */
    private static int[] computeOffsets(List<Instruction> insns) {
        int[] offsets = new int[insns.size()];
        int offset = 0;
        for (int i = 0; i < insns.size(); i++) {
            offsets[i] = offset;
            offset += encodedSize(insns.get(i));
        }
        return offsets;
    }

    private static boolean isBranch(Opcode op) {
        switch (op) {
            case IFEQ: case IFNE: case IFLT: case IFGE: case IFGT: case IFLE:
            case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE:
            case IF_ICMPGT: case IF_ICMPLE:
            case IF_ACMPEQ: case IF_ACMPNE:
            case IFNULL: case IFNONNULL:
            case GOTO:
                return true;
            default:
                return false;
        }
    }

    private static int encodedSize(Instruction insn) {
        int size = 1; // opcode byte
        for (long operand : insn.operands()) {
            size += varintSize(operand);
        }
        return size;
    }

    /**
     * Compute how many bytes a value would take as signed LEB128.
     * Must match Encoder.writeSignedLeb128 exactly.
     */
    private static int varintSize(long value) {
        int size = 0;
        while (true) {
            size++;
            byte b = (byte) (value & 0x7F);
            value >>= 7;
            if ((value == 0 && (b & 0x40) == 0) || (value == -1 && (b & 0x40) != 0)) {
                break;
            }
        }
        return size;
    }
}
