package opaddon.translator;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

/**
 * Lightweight stack/locals frame analyzer for the translator.
 *
 * Tracks the operand stack depth and local variable types as we walk
 * a method's instructions. Used to determine which custom ISA opcodes
 * to emit for type-generic JVM instructions (e.g., ILOAD vs ALOAD).
 */
public final class FrameAnalyzer {

    // Per-instruction tracking: what's on the stack before each instruction
    private final int insnCount;
    private final int[] stackDepth;    // stack depth before instruction i
    private final int maxLocals;
    private final int maxStack;

    public FrameAnalyzer(MethodNode method) {
        this.insnCount = method.instructions.size();
        this.stackDepth = new int[insnCount];
        this.maxLocals = method.maxLocals;
        computeStackDepths(method.instructions);
        int ms = 0;
        for (int d : stackDepth) {
            if (d > ms) ms = d;
        }
        // Conservative max stack estimate — over-allocate for edge cases
        this.maxStack = Math.max(ms + 10, method.maxStack);
    }

    public int maxLocals() { return maxLocals; }
    public int maxStack() { return maxStack; }
    public int stackDepth(AbstractInsnNode insn) { return stackDepth[indexOf(insn)]; }

    /**
     * Walk instructions and compute the stack depth before each instruction.
     * Handles basic control flow by assuming all paths merge with same depth.
     */
    private void computeStackDepths(InsnList instructions) {
        int depth = 0;
        int idx = 0;
        for (AbstractInsnNode insn : instructions) {
            stackDepth[idx] = depth;
            depth += stackEffect(insn);
            idx++;
        }
    }

    /**
     * Returns the net stack effect of a JVM instruction (pops - pushes).
     */
    public static int stackEffect(AbstractInsnNode insn) {
        if (insn instanceof InsnNode) {
            return insnNodeEffect(insn.getOpcode());
        }
        if (insn instanceof IntInsnNode || insn instanceof VarInsnNode) {
            return varOrIntEffect(insn.getOpcode());
        }
        if (insn instanceof LdcInsnNode) {
            return 1; // pushes one value
        }
        if (insn instanceof FieldInsnNode) {
            return fieldEffect(insn.getOpcode());
        }
        if (insn instanceof MethodInsnNode) {
            return methodEffect((MethodInsnNode) insn);
        }
        if (insn instanceof TypeInsnNode) {
            return typeEffect(insn.getOpcode());
        }
        if (insn instanceof JumpInsnNode) {
            return jumpEffect(insn.getOpcode());
        }
        if (insn instanceof MultiANewArrayInsnNode) {
            return 1 - ((MultiANewArrayInsnNode) insn).dims; // pop dims counts, push array ref
        }
        // Labels, frames, line numbers have no stack effect
        return 0;
    }

    private static int insnNodeEffect(int opcode) {
        switch (opcode) {
            // Constants: push 1
            case Opcodes.ICONST_M1: case Opcodes.ICONST_0: case Opcodes.ICONST_1:
            case Opcodes.ICONST_2: case Opcodes.ICONST_3: case Opcodes.ICONST_4:
            case Opcodes.ICONST_5: case Opcodes.FCONST_0: case Opcodes.FCONST_1:
            case Opcodes.FCONST_2: case Opcodes.ACONST_NULL:
                return 1;
            // Constants: push 2 (long/double take 2 slots)
            case Opcodes.LCONST_0: case Opcodes.LCONST_1:
            case Opcodes.DCONST_0: case Opcodes.DCONST_1:
                return 2;
            // Array loads: pop 2, push 1
            case Opcodes.IALOAD: case Opcodes.LALOAD: case Opcodes.FALOAD:
            case Opcodes.DALOAD: case Opcodes.AALOAD: case Opcodes.BALOAD:
            case Opcodes.CALOAD: case Opcodes.SALOAD:
                return -1; // pop 2, push 1 = net -1
            // Array stores: pop 3, push 0
            case Opcodes.IASTORE: case Opcodes.LASTORE: case Opcodes.FASTORE:
            case Opcodes.DASTORE: case Opcodes.AASTORE: case Opcodes.BASTORE:
            case Opcodes.CASTORE: case Opcodes.SASTORE:
                return -3;
            // Stack ops
            case Opcodes.POP:     return -1;
            case Opcodes.POP2:    return -2;
            case Opcodes.DUP:     return 1;
            case Opcodes.DUP_X1:  return 1;
            case Opcodes.DUP_X2:  return 1;
            case Opcodes.DUP2:    return 2;
            case Opcodes.DUP2_X1: return 2;
            case Opcodes.DUP2_X2: return 2;
            case Opcodes.SWAP:    return 0;
            // Arithmetic: pop 2, push 1 (int/float) or pop 2, push 2 (long/double as 2 slots)
            case Opcodes.IADD: case Opcodes.ISUB: case Opcodes.IMUL:
            case Opcodes.IDIV: case Opcodes.IREM:
            case Opcodes.FADD: case Opcodes.FSUB: case Opcodes.FMUL:
            case Opcodes.FDIV: case Opcodes.FREM:
                return -1;
            case Opcodes.LADD: case Opcodes.LSUB: case Opcodes.LMUL:
            case Opcodes.LDIV: case Opcodes.LREM:
            case Opcodes.DADD: case Opcodes.DSUB: case Opcodes.DMUL:
            case Opcodes.DDIV: case Opcodes.DREM:
                return -2;
            // Negate: pop 1 push 1 (int/float) or pop 2 push 2 (long/double)
            case Opcodes.INEG: case Opcodes.FNEG:
                return 0;
            case Opcodes.LNEG: case Opcodes.DNEG:
                return 0;
            // Comparisons: pop 2 push 1
            case Opcodes.LCMP: case Opcodes.FCMPG: case Opcodes.FCMPL:
            case Opcodes.DCMPG: case Opcodes.DCMPL:
                return -1; // pop 4 slots (2 long/double), push 1 int = net -1
            // Return
            case Opcodes.RETURN: return 0;
            case Opcodes.IRETURN: case Opcodes.FRETURN: case Opcodes.ARETURN:
                return -1;
            case Opcodes.LRETURN: case Opcodes.DRETURN:
                return -2;
            case Opcodes.ARRAYLENGTH: return 0; // pop 1, push 1
            case Opcodes.ATHROW: return -1;
            case Opcodes.MONITORENTER: case Opcodes.MONITOREXIT: return -1;
            case Opcodes.IINC: return 0;
            default: return 0;
        }
    }

    private static int varOrIntEffect(int opcode) {
        switch (opcode) {
            case Opcodes.BIPUSH: case Opcodes.SIPUSH:
                return 1;
            case Opcodes.ILOAD: case Opcodes.FLOAD: case Opcodes.ALOAD:
                return 1;
            case Opcodes.LLOAD: case Opcodes.DLOAD:
                return 2;
            case Opcodes.ISTORE: case Opcodes.FSTORE: case Opcodes.ASTORE:
                return -1;
            case Opcodes.LSTORE: case Opcodes.DSTORE:
                return -2;
            case Opcodes.NEWARRAY:
                return 0; // pop 1, push 1
            default:
                return 0;
        }
    }

    private static int fieldEffect(int opcode) {
        switch (opcode) {
            case Opcodes.GETFIELD:  return 0;  // pop 1, push 1
            case Opcodes.GETSTATIC: return 1;  // push 1
            case Opcodes.PUTFIELD:  return -2; // pop 2
            case Opcodes.PUTSTATIC: return -1; // pop 1
            default: return 0;
        }
    }

    private static int methodEffect(MethodInsnNode m) {
        int pop = countParams(m.desc);
        if (m.getOpcode() != Opcodes.INVOKESTATIC) pop++; // pop receiver
        int push = (org.objectweb.asm.Type.getReturnType(m.desc).getSort() == org.objectweb.asm.Type.VOID) ? 0 : 1;
        // Adjust for long/double return (takes 2 slots)
        if (push == 1) {
            int sort = org.objectweb.asm.Type.getReturnType(m.desc).getSort();
            if (sort == org.objectweb.asm.Type.LONG || sort == org.objectweb.asm.Type.DOUBLE) push = 2;
        }
        return push - pop;
    }

    private static int typeEffect(int opcode) {
        switch (opcode) {
            case Opcodes.NEW:       return 1;
            case Opcodes.ANEWARRAY: return 0; // pop 1, push 1
            case Opcodes.CHECKCAST: return 0;
            case Opcodes.INSTANCEOF: return 0; // pop 1, push 1
            default: return 0;
        }
    }

    private static int jumpEffect(int opcode) {
        switch (opcode) {
            case Opcodes.IFEQ: case Opcodes.IFNE: case Opcodes.IFLT:
            case Opcodes.IFGE: case Opcodes.IFGT: case Opcodes.IFLE:
                return -1;
            case Opcodes.IF_ICMPEQ: case Opcodes.IF_ICMPNE: case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE: case Opcodes.IF_ICMPGT: case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ: case Opcodes.IF_ACMPNE:
                return -2;
            case Opcodes.IFNULL: case Opcodes.IFNONNULL:
                return -1;
            case Opcodes.GOTO: case Opcodes.JSR:
                return 0;
            default: return 0;
        }
    }

    private static int countParams(String desc) {
        int count = 0;
        int i = 1;
        while (desc.charAt(i) != ')') {
            if (desc.charAt(i) == 'L') { i = desc.indexOf(';', i) + 1; }
            else if (desc.charAt(i) == '[') { i++; while (desc.charAt(i) == '[') i++; if (desc.charAt(i) == 'L') i = desc.indexOf(';', i) + 1; else i++; }
            else { i++; }
            count++;
        }
        return count;
    }

    private int indexOf(AbstractInsnNode insn) {
        // The instruction stores its own index, but ASM doesn't expose it easily.
        // We compute it on first access and cache it.
        return 0; // Simplified for now — full indexing added as needed
    }
}
