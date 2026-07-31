package opaddon.translator;

import opaddon.isa.Instruction;
import opaddon.isa.Opcode;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Translates a JVM method (ASM MethodNode) into a custom ISA program
 * plus a constant table.
 *
 * <pre>
 *   TranslationResult result = MethodTranslator.translate(methodNode);
 *   byte[] program = result.program();
 *   Object[] constants = result.constants();
 * </pre>
 */
public final class MethodTranslator {

    private MethodTranslator() {}

    /**
     * Exception handler info: each entry is [start_pc, end_pc, handler_pc, type_const_idx].
     * type_const_idx of -1 means "finally" (catches all exceptions).
     */
    public record TranslationResult(List<Instruction> instructions, Object[] constants,
                                     int[][] exceptionHandlers,
                                     byte[] forwardMapping, byte[] reverseMapping) {
        /** Encode instructions + exception handler header + optional shuffle into a byte array. */
        public byte[] program() {
            return opaddon.isa.Encoder.encodeWithHeader(
                instructions, exceptionHandlers, forwardMapping, reverseMapping);
        }
    }

    /**
     * Translate a method's JVM bytecode into custom ISA instructions.
     *
     * @param method the ASM MethodNode to translate
     * @return translated instructions + constant table
     */
    public static TranslationResult translate(MethodNode method, long seed) {
        Context ctx = new Context(method, seed);
        ctx.translate();
        return new TranslationResult(ctx.instructions, ctx.constants.toArray(),
            ctx.exceptionHandlers.toArray(new int[0][]),
            ctx.forwardMapping, ctx.reverseMapping);
    }

    /** Backward-compatible: translate without shuffle */
    public static TranslationResult translate(MethodNode method) {
        return translate(method, 0);
    }

    // --- Internal context ---

    private static final class Context {
        final MethodNode method;
        final List<Instruction> instructions = new ArrayList<>();
        final List<Object> constants = new ArrayList<>();
        final Map<String, Integer> constantIndex = new HashMap<>();
        final Map<LabelNode, Integer> labelToInsnIndex = new HashMap<>();
        final List<int[]> exceptionHandlers = new ArrayList<>();
        // Temporary storage for handlers: [start_label, end_label, handler_label, type]
        final List<Object[]> pendingHandlers = new ArrayList<>();
        final byte[] forwardMapping;
        final byte[] reverseMapping;

        Context(MethodNode method, long seed) {
            this.method = method;
            // Opcode shuffle disabled by default — XOR encryption provides
            // sufficient hardening. Enable explicitly for per-build randomization.
            this.forwardMapping = null;
            this.reverseMapping = null;
        }

        void translate() {
            // Pre-pass: compute ISA instruction index for each JVM instruction position
            precomputeLabelIndices();

            // Collect exception handlers
            for (TryCatchBlockNode tc : method.tryCatchBlocks) {
                // type is internal class name or null for finally
                int typeIdx = (tc.type == null) ? -1 : constIdx(tc.type);
                pendingHandlers.add(new Object[]{tc.start, tc.end, tc.handler, typeIdx});
            }

            // Emit pass: translate each JVM instruction
            for (AbstractInsnNode insn : method.instructions) {
                if (insn.getType() == AbstractInsnNode.LABEL ||
                    insn.getType() == AbstractInsnNode.LINE ||
                    insn.getType() == AbstractInsnNode.FRAME) {
                    continue;
                }

                switch (insn.getType()) {
                    case AbstractInsnNode.INSN:
                        translateInsn((InsnNode) insn); break;
                    case AbstractInsnNode.INT_INSN:
                        translateIntInsn((IntInsnNode) insn); break;
                    case AbstractInsnNode.VAR_INSN:
                        translateVarInsn((VarInsnNode) insn); break;
                    case AbstractInsnNode.LDC_INSN:
                        translateLdcInsn((LdcInsnNode) insn); break;
                    case AbstractInsnNode.TYPE_INSN:
                        translateTypeInsn((TypeInsnNode) insn); break;
                    case AbstractInsnNode.FIELD_INSN:
                        translateFieldInsn((FieldInsnNode) insn); break;
                    case AbstractInsnNode.METHOD_INSN:
                        translateMethodInsn((MethodInsnNode) insn); break;
                    case AbstractInsnNode.JUMP_INSN:
                        translateJumpInsn((JumpInsnNode) insn); break;
                    case AbstractInsnNode.MULTIANEWARRAY_INSN:
                        translateMultiANewArray((MultiANewArrayInsnNode) insn); break;
                    case AbstractInsnNode.IINC_INSN:
                        translateIinc((IincInsnNode) insn); break;
                    case AbstractInsnNode.TABLESWITCH_INSN:
                        translateTableSwitch((TableSwitchInsnNode) insn); break;
                    case AbstractInsnNode.LOOKUPSWITCH_INSN:
                        translateLookupSwitch((LookupSwitchInsnNode) insn); break;
                    case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
                        translateInvokeDynamic((InvokeDynamicInsnNode) insn); break;
                    default: break;
                }
            }

            resolveBranches();
        }

        /**
         * Pre-compute label → ISA instruction index by walking JVM instructions
         * and counting how many ISA instructions each JVM instruction expands to.
         * This handles forward branches (jumps to labels that appear later).
         */
        private void precomputeLabelIndices() {
            int isaIdx = 0;
            for (AbstractInsnNode insn : method.instructions) {
                if (insn.getType() == AbstractInsnNode.LABEL) {
                    labelToInsnIndex.put((LabelNode) insn, isaIdx);
                    continue;
                }
                if (insn.getType() == AbstractInsnNode.LINE ||
                    insn.getType() == AbstractInsnNode.FRAME) {
                    continue;
                }
                // Count ISA instructions this JVM instruction expands to
                if (insn.getType() == AbstractInsnNode.IINC_INSN) {
                    isaIdx += 4; // ILOAD, ICONST, IADD, ISTORE
                } else if (insn.getType() == AbstractInsnNode.TABLESWITCH_INSN) {
                    TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                    isaIdx += ts.labels.size() * 3 + 2; // DUP+ICONST+IF_ICMPEQ per case + POP+GOTO
                } else if (insn.getType() == AbstractInsnNode.LOOKUPSWITCH_INSN) {
                    LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                    isaIdx += ls.labels.size() * 3 + 2;
                } else if (insn.getType() == AbstractInsnNode.INVOKE_DYNAMIC_INSN) {
                    isaIdx += 10; // NEW + INVOKESPECIAL + N*append + toString
                } else {
                    isaIdx += 1;
                }
            }
        }

        // --- Instruction translation ---

        private void translateInsn(InsnNode insn) {
            int op = insn.getOpcode();
            switch (op) {
                // Integer constants
                case Opcodes.ICONST_M1: emit(Instruction.iconst(-1)); break;
                case Opcodes.ICONST_0:  emit(Instruction.iconst(0)); break;
                case Opcodes.ICONST_1:  emit(Instruction.iconst(1)); break;
                case Opcodes.ICONST_2:  emit(Instruction.iconst(2)); break;
                case Opcodes.ICONST_3:  emit(Instruction.iconst(3)); break;
                case Opcodes.ICONST_4:  emit(Instruction.iconst(4)); break;
                case Opcodes.ICONST_5:  emit(Instruction.iconst(5)); break;

                // Long constants
                case Opcodes.LCONST_0: emit(Instruction.lconst(0L)); break;
                case Opcodes.LCONST_1: emit(Instruction.lconst(1L)); break;

                // Float constants
                case Opcodes.FCONST_0: emit(Instruction.fconst(0.0f)); break;
                case Opcodes.FCONST_1: emit(Instruction.fconst(1.0f)); break;
                case Opcodes.FCONST_2: emit(Instruction.fconst(2.0f)); break;

                // Double constants
                case Opcodes.DCONST_0: emit(Instruction.dconst(0.0)); break;
                case Opcodes.DCONST_1: emit(Instruction.dconst(1.0)); break;

                // Null
                case Opcodes.ACONST_NULL: emit(Instruction.ldc(constIdx(null))); break;

                // Integer arithmetic
                case Opcodes.IADD: emit(Instruction.iadd()); break;
                case Opcodes.ISUB: emit(Instruction.isub()); break;
                case Opcodes.IMUL: emit(Instruction.imul()); break;
                case Opcodes.IDIV: emit(Instruction.idiv()); break;
                case Opcodes.IREM: emit(Instruction.irem()); break;
                case Opcodes.INEG: emit(Instruction.ineg()); break;

                // Long arithmetic
                case Opcodes.LADD: emit(Instruction.ladd()); break;
                case Opcodes.LSUB: emit(Instruction.lsub()); break;
                case Opcodes.LMUL: emit(Instruction.lmul()); break;
                case Opcodes.LDIV: emit(Instruction.ldiv()); break;
                case Opcodes.LREM: emit(Instruction.lrem()); break;
                case Opcodes.LNEG: emit(Instruction.lneg()); break;

                // Integer bitwise
                case Opcodes.IAND: emit(Instruction.iand()); break;
                case Opcodes.IOR:  emit(Instruction.ior()); break;
                case Opcodes.IXOR: emit(Instruction.ixor()); break;
                case Opcodes.ISHL: emit(Instruction.ishl()); break;
                case Opcodes.ISHR: emit(Instruction.ishr()); break;
                case Opcodes.IUSHR:emit(Instruction.iushr()); break;
                // Long bitwise
                case Opcodes.LAND: emit(Instruction.land()); break;
                case Opcodes.LOR:  emit(Instruction.lor()); break;
                case Opcodes.LXOR: emit(Instruction.lxor()); break;
                case Opcodes.LSHL: emit(Instruction.lshl()); break;
                case Opcodes.LSHR: emit(Instruction.lshr()); break;
                case Opcodes.LUSHR:emit(Instruction.lushr()); break;

                // Float arithmetic
                case Opcodes.FADD: emit(Instruction.fadd()); break;
                case Opcodes.FSUB: emit(Instruction.fsub()); break;
                case Opcodes.FMUL: emit(Instruction.fmul()); break;
                case Opcodes.FDIV: emit(Instruction.fdiv()); break;
                case Opcodes.FREM: emit(Instruction.frem()); break;
                case Opcodes.FNEG: emit(Instruction.fneg()); break;

                // Double arithmetic
                case Opcodes.DADD: emit(Instruction.dadd()); break;
                case Opcodes.DSUB: emit(Instruction.dsub()); break;
                case Opcodes.DMUL: emit(Instruction.dmul()); break;
                case Opcodes.DDIV: emit(Instruction.ddiv()); break;
                case Opcodes.DREM: emit(Instruction.drem()); break;
                case Opcodes.DNEG: emit(Instruction.dneg()); break;

                // Comparisons
                case Opcodes.LCMP:  emit(Instruction.lcmp()); break;
                case Opcodes.FCMPG: emit(Instruction.fcmpg()); break;
                case Opcodes.FCMPL: emit(Instruction.fcmpl()); break;
                case Opcodes.DCMPG: emit(Instruction.dcmpg()); break;
                case Opcodes.DCMPL: emit(Instruction.dcmpl()); break;

                // Array loads
                case Opcodes.IALOAD: emit(Instruction.iaload()); break;
                case Opcodes.LALOAD: emit(Instruction.laload()); break;
                case Opcodes.FALOAD: emit(Instruction.faload()); break;
                case Opcodes.DALOAD: emit(Instruction.daload()); break;
                case Opcodes.AALOAD: emit(Instruction.aaload()); break;
                case Opcodes.BALOAD: emit(Instruction.baload()); break;
                case Opcodes.CALOAD: emit(Instruction.caload()); break;
                case Opcodes.SALOAD: emit(Instruction.saload()); break;

                // Array stores
                case Opcodes.IASTORE: emit(Instruction.iastore()); break;
                case Opcodes.LASTORE: emit(Instruction.lastore()); break;
                case Opcodes.FASTORE: emit(Instruction.fastore()); break;
                case Opcodes.DASTORE: emit(Instruction.dastore()); break;
                case Opcodes.AASTORE: emit(Instruction.aastore()); break;
                case Opcodes.BASTORE: emit(Instruction.bastore()); break;
                case Opcodes.CASTORE: emit(Instruction.castore()); break;
                case Opcodes.SASTORE: emit(Instruction.sastore()); break;

                // Stack manipulation
                case Opcodes.DUP:     emit(Instruction.dup()); break;
                case Opcodes.DUP_X1:  emit(Instruction.dup_x1()); break;
                case Opcodes.DUP_X2:  emit(Instruction.dup_x2()); break;
                case Opcodes.DUP2:    emit(Instruction.dup2()); break;
                case Opcodes.DUP2_X1: emit(Instruction.dup2_x1()); break;
                case Opcodes.DUP2_X2: emit(Instruction.dup2_x2()); break;
                case Opcodes.POP:     emit(Instruction.pop()); break;
                case Opcodes.POP2:    emit(Instruction.pop2()); break;
                case Opcodes.SWAP:    emit(Instruction.swap()); break;

                // Array length
                case Opcodes.ARRAYLENGTH: emit(Instruction.arraylength()); break;

                // Returns
                case Opcodes.RETURN:  emit(Instruction.return_()); break;
                case Opcodes.IRETURN: emit(Instruction.ireturn()); break;
                case Opcodes.LRETURN: emit(Instruction.lreturn()); break;
                case Opcodes.FRETURN: emit(Instruction.freturn()); break;
                case Opcodes.DRETURN: emit(Instruction.dreturn()); break;
                case Opcodes.ARETURN: emit(Instruction.areturn()); break;

                case Opcodes.MONITORENTER: emit(Instruction.monitorenter()); break;
                case Opcodes.MONITOREXIT:  emit(Instruction.monitorexit()); break;
                case Opcodes.ATHROW: emit(Instruction.athrow()); break;
                // Primitive conversions
                case Opcodes.I2L: emit(Instruction.i2l()); break;
                case Opcodes.I2F: emit(Instruction.i2f()); break;
                case Opcodes.I2D: emit(Instruction.i2d()); break;
                case Opcodes.L2I: emit(Instruction.l2i()); break;
                case Opcodes.L2F: emit(Instruction.l2f()); break;
                case Opcodes.L2D: emit(Instruction.l2d()); break;
                case Opcodes.F2I: emit(Instruction.f2i()); break;
                case Opcodes.F2L: emit(Instruction.f2l()); break;
                case Opcodes.F2D: emit(Instruction.f2d()); break;
                case Opcodes.D2I: emit(Instruction.d2i()); break;
                case Opcodes.D2L: emit(Instruction.d2l()); break;
                case Opcodes.D2F: emit(Instruction.d2f()); break;
                case Opcodes.I2B: emit(Instruction.i2b()); break;
                case Opcodes.I2C: emit(Instruction.i2c()); break;
                case Opcodes.I2S: emit(Instruction.i2s()); break;

                // Shorthand load: 0x1A-0x2D → ILOAD_0..ALOAD_3
                case 0x1A: emit(Instruction.iload(0)); break;
                case 0x1B: emit(Instruction.iload(1)); break;
                case 0x1C: emit(Instruction.iload(2)); break;
                case 0x1D: emit(Instruction.iload(3)); break;
                case 0x1E: emit(Instruction.lload(0)); break;
                case 0x1F: emit(Instruction.lload(1)); break;
                case 0x20: emit(Instruction.lload(2)); break;
                case 0x21: emit(Instruction.lload(3)); break;
                case 0x22: emit(Instruction.fload(0)); break;
                case 0x23: emit(Instruction.fload(1)); break;
                case 0x24: emit(Instruction.fload(2)); break;
                case 0x25: emit(Instruction.fload(3)); break;
                case 0x26: emit(Instruction.dload(0)); break;
                case 0x27: emit(Instruction.dload(1)); break;
                case 0x28: emit(Instruction.dload(2)); break;
                case 0x29: emit(Instruction.dload(3)); break;
                case 0x2A: emit(Instruction.aload(0)); break;
                case 0x2B: emit(Instruction.aload(1)); break;
                case 0x2C: emit(Instruction.aload(2)); break;
                case 0x2D: emit(Instruction.aload(3)); break;
                // Shorthand store: 0x3B-0x4E → ISTORE_0..ASTORE_3
                case 0x3B: emit(Instruction.istore(0)); break;
                case 0x3C: emit(Instruction.istore(1)); break;
                case 0x3D: emit(Instruction.istore(2)); break;
                case 0x3E: emit(Instruction.istore(3)); break;
                case 0x3F: emit(Instruction.lstore(0)); break;
                case 0x40: emit(Instruction.lstore(1)); break;
                case 0x41: emit(Instruction.lstore(2)); break;
                case 0x42: emit(Instruction.lstore(3)); break;
                case 0x43: emit(Instruction.fstore(0)); break;
                case 0x44: emit(Instruction.fstore(1)); break;
                case 0x45: emit(Instruction.fstore(2)); break;
                case 0x46: emit(Instruction.fstore(3)); break;
                case 0x47: emit(Instruction.dstore(0)); break;
                case 0x48: emit(Instruction.dstore(1)); break;
                case 0x49: emit(Instruction.dstore(2)); break;
                case 0x4A: emit(Instruction.dstore(3)); break;
                case 0x4B: emit(Instruction.astore(0)); break;
                case 0x4C: emit(Instruction.astore(1)); break;
                case 0x4D: emit(Instruction.astore(2)); break;
                case 0x4E: emit(Instruction.astore(3)); break;

                case Opcodes.NOP: emit(Instruction.nop()); break;

                default:
                    throw new UnsupportedOperationException(
                        "Unsupported insn opcode: " + op + " (" + OpcodesUtil.opcodeName(op) + ")");
            }
        }

        private void translateIntInsn(IntInsnNode insn) {
            int op = insn.getOpcode();
            switch (op) {
                case Opcodes.BIPUSH:
                case Opcodes.SIPUSH:
                    emit(Instruction.iconst(insn.operand));
                    break;
                case Opcodes.NEWARRAY:
                    emit(Instruction.newarray(insn.operand));
                    break;
                default:
                    throw new UnsupportedOperationException(
                        "Unsupported int insn: " + op);
            }
        }

        private void translateVarInsn(VarInsnNode insn) {
            int op = insn.getOpcode();
            int slot = insn.var;
            switch (op) {
                case Opcodes.ILOAD:  emit(Instruction.iload(slot)); break;
                case Opcodes.LLOAD:  emit(Instruction.lload(slot)); break;
                case Opcodes.FLOAD:  emit(Instruction.fload(slot)); break;
                case Opcodes.DLOAD:  emit(Instruction.dload(slot)); break;
                case Opcodes.ALOAD:  emit(Instruction.aload(slot)); break;
                case Opcodes.ISTORE: emit(Instruction.istore(slot)); break;
                case Opcodes.LSTORE: emit(Instruction.lstore(slot)); break;
                case Opcodes.FSTORE: emit(Instruction.fstore(slot)); break;
                case Opcodes.DSTORE: emit(Instruction.dstore(slot)); break;
                case Opcodes.ASTORE: emit(Instruction.astore(slot)); break;
                default:
                    throw new UnsupportedOperationException(
                        "Unsupported var insn: " + op);
            }
        }

        private void translateLdcInsn(LdcInsnNode insn) {
            Object cst = insn.cst;
            if (cst instanceof Integer || cst instanceof Long || cst instanceof Float
                || cst instanceof Double || cst instanceof String || cst instanceof Type) {
                int idx = constIdx(cst);
                emit(Instruction.ldc(idx));
            } else {
                throw new UnsupportedOperationException(
                    "Unsupported LDC constant type: " + cst.getClass().getName());
            }
        }

        private void translateTypeInsn(TypeInsnNode insn) {
            int op = insn.getOpcode();
            String desc = insn.desc;
            switch (op) {
                case Opcodes.NEW:
                    emit(Instruction.new_(constIdx(desc)));
                    break;
                case Opcodes.ANEWARRAY:
                    emit(Instruction.anewarray(constIdx(desc)));
                    break;
                case Opcodes.CHECKCAST:
                    emit(Instruction.checkcast(constIdx(desc)));
                    break;
                case Opcodes.INSTANCEOF:
                    emit(Instruction.instanceof_(constIdx(desc)));
                    break;
                default:
                    throw new UnsupportedOperationException(
                        "Unsupported type insn: " + op);
            }
        }

        private void translateFieldInsn(FieldInsnNode insn) {
            String[] desc = {insn.owner, insn.name, insn.desc};
            int idx = constIdx(desc);
            switch (insn.getOpcode()) {
                case Opcodes.GETFIELD:  emit(Instruction.getfield(idx)); break;
                case Opcodes.PUTFIELD:  emit(Instruction.putfield(idx)); break;
                case Opcodes.GETSTATIC: emit(Instruction.getstatic(idx)); break;
                case Opcodes.PUTSTATIC: emit(Instruction.putstatic(idx)); break;
                default:
                    throw new UnsupportedOperationException(
                        "Unsupported field insn: " + insn.getOpcode());
            }
        }

        private void translateMethodInsn(MethodInsnNode insn) {
            String[] desc = {insn.owner, insn.name, insn.desc};
            int idx = constIdx(desc);
            switch (insn.getOpcode()) {
                case Opcodes.INVOKESTATIC:   emit(Instruction.invokestatic(idx)); break;
                case Opcodes.INVOKEVIRTUAL:  emit(Instruction.invokevirtual(idx)); break;
                case Opcodes.INVOKESPECIAL:  emit(Instruction.invokespecial(idx)); break;
                case Opcodes.INVOKEINTERFACE: emit(Instruction.invokeinterface(idx)); break;
                default:
                    throw new UnsupportedOperationException(
                        "Unsupported method insn: " + insn.getOpcode());
            }
        }

        private void translateJumpInsn(JumpInsnNode insn) {
            int op = insn.getOpcode();
            // For Phase 3: jumps are emitted with placeholder targets.
            // Phase 4 resolves them using labelToInsnIndex.
            int targetIdx = labelIndex(insn.label);
            switch (op) {
                case Opcodes.IFEQ:      emit(Instruction.ifeq(targetIdx)); break;
                case Opcodes.IFNE:      emit(Instruction.ifne(targetIdx)); break;
                case Opcodes.IFLT:      emit(Instruction.iflt(targetIdx)); break;
                case Opcodes.IFGE:      emit(Instruction.ifge(targetIdx)); break;
                case Opcodes.IFGT:      emit(Instruction.ifgt(targetIdx)); break;
                case Opcodes.IFLE:      emit(Instruction.ifle(targetIdx)); break;
                case Opcodes.IF_ICMPEQ: emit(Instruction.if_icmpeq(targetIdx)); break;
                case Opcodes.IF_ICMPNE: emit(Instruction.if_icmpne(targetIdx)); break;
                case Opcodes.IF_ICMPLT: emit(Instruction.if_icmplt(targetIdx)); break;
                case Opcodes.IF_ICMPGE: emit(Instruction.if_icmpge(targetIdx)); break;
                case Opcodes.IF_ICMPGT: emit(Instruction.if_icmpgt(targetIdx)); break;
                case Opcodes.IF_ICMPLE: emit(Instruction.if_icmple(targetIdx)); break;
                case Opcodes.IF_ACMPEQ: emit(Instruction.if_acmpeq(targetIdx)); break;
                case Opcodes.IF_ACMPNE: emit(Instruction.if_acmpne(targetIdx)); break;
                case Opcodes.IFNULL:    emit(Instruction.ifnull(targetIdx)); break;
                case Opcodes.IFNONNULL: emit(Instruction.ifnonnull(targetIdx)); break;
                case Opcodes.GOTO:      emit(Instruction.goto_(targetIdx)); break;
                default:
                    throw new UnsupportedOperationException(
                        "Unsupported jump insn: " + op);
            }
        }

        private void translateIinc(IincInsnNode insn) {
            // IINC var incr → ILOAD var; ICONST incr; IADD; ISTORE var
            emit(Instruction.iload(insn.var));
            emit(Instruction.iconst(insn.incr));
            emit(Instruction.iadd());
            emit(Instruction.istore(insn.var));
        }

        private void translateTableSwitch(TableSwitchInsnNode insn) {
            // Expand tableswitch into IF_ICMPEQ + GOTO chain
            // Key is on top of stack
            int[] keys = new int[insn.labels.size()];
            for (int i = 0; i < keys.length; i++) {
                keys[i] = insn.min + i;
            }
            emitSwitch(keys, insn.labels, insn.dflt);
        }

        private void translateLookupSwitch(LookupSwitchInsnNode insn) {
            int[] keys = new int[insn.keys.size()];
            for (int i = 0; i < keys.length; i++) {
                keys[i] = insn.keys.get(i);
            }
            emitSwitch(keys, insn.labels, insn.dflt);
        }

        private void emitSwitch(int[] keys, java.util.List<LabelNode> labels, LabelNode dflt) {
            // For each case: DUP; ICONST key; IF_ICMPEQ case_label
            // After all cases: POP; GOTO default_label
            for (int i = 0; i < keys.length; i++) {
                emit(Instruction.dup());                         // duplicate key
                emit(Instruction.iconst(keys[i]));               // push case value
                emit(Instruction.if_icmpeq(labelIndex(labels.get(i)))); // branch if equal
            }
            emit(Instruction.pop());                             // discard key
            emit(Instruction.goto_(labelIndex(dflt)));           // jump to default
        }

        private void translateInvokeDynamic(InvokeDynamicInsnNode insn) {
            if (insn.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) {
                translateStringConcat(insn); return;
            }
            throw new UnsupportedOperationException("indy: " + insn.bsm.getOwner());
        }

        private void translateStringConcat(InvokeDynamicInsnNode insn) {
            String recipe = (String) insn.bsmArgs[0];
            int sbCtor = constIdx(new String[]{"java/lang/StringBuilder","<init>","()V"});
            int appStr = constIdx(new String[]{"java/lang/StringBuilder","append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;"});
            int appObj = constIdx(new String[]{"java/lang/StringBuilder","append",
                "(Ljava/lang/Object;)Ljava/lang/StringBuilder;"});
            int toStr = constIdx(new String[]{"java/lang/StringBuilder","toString",
                "()Ljava/lang/String;"});

            // Count args from recipe, pop from stack into temp locals
            int argCount = 0;
            for (int i = 0; i < recipe.length(); i++)
                if (recipe.charAt(i) == '') argCount++;
            int base = 200;
            for (int a = argCount - 1; a >= 0; a--)
                emit(Instruction.astore(base + a));

            // Build: NEW StringBuilder; INVOKESPECIAL <init>
            emit(Instruction.new_(constIdx("java/lang/StringBuilder")));
            emit(Instruction.invokespecial(sbCtor));

            // Parse recipe: emit append calls for each element
            int ai = 0, ci = 0;
            StringBuilder lit = new StringBuilder();
            for (int i = 0; i < recipe.length(); i++) {
                char c = recipe.charAt(i);
                if (c == '') {
                    flushLit(lit, appStr); i++;
                    emit(Instruction.aload(base + ai));
                    emit(Instruction.invokevirtual(appObj)); ai++;
                } else if (c == '') {
                    flushLit(lit, appStr); i++;
                    emit(Instruction.ldc(constIdx(insn.bsmArgs[1 + ci])));
                    emit(Instruction.invokevirtual(appStr)); ci++;
                } else { lit.append(c); }
            }
            flushLit(lit, appStr);
            emit(Instruction.invokevirtual(toStr));
        }

        private void flushLit(StringBuilder lit, int appStrIdx) {
            if (lit.length() == 0) return;
            emit(Instruction.ldc(constIdx(lit.toString())));
            emit(Instruction.invokevirtual(appStrIdx));
            lit.setLength(0);
        }

        private void translateMultiANewArray(MultiANewArrayInsnNode insn) {
            throw new UnsupportedOperationException(
                "MULTIANEWARRAY not yet supported");
        }

        // --- Helpers ---

        private void emit(Instruction insn) {
            instructions.add(insn);
        }

        /** Add a constant to the table and return its index. */
        private int constIdx(Object value) {
            String key = constantKey(value);
            return constantIndex.computeIfAbsent(key, k -> {
                int idx = constants.size();
                constants.add(value);
                return idx;
            });
        }

        private static String constantKey(Object value) {
            if (value instanceof String[]) {
                String[] arr = (String[]) value;
                return "S[" + arr[0] + "." + arr[1] + arr[2] + "]";
            }
            return String.valueOf(value);
        }

        /** Get the instruction index that a label points to. */
        private int labelIndex(LabelNode label) {
            Integer idx = labelToInsnIndex.get(label);
            if (idx == null) {
                throw new IllegalStateException("Label not found: " + label);
            }
            return idx;
        }

        // --- Branch resolution (Phase 4) ---
        // For now, just a placeholder; Phase 4 will fill in proper offset computation.

        private void resolveBranches() {
            // Compute byte offsets of instructions (relative to instruction start)
            int[] offsets = computeOffsets();

            // Determine header size (including shuffle flag + optional mapping)
            boolean hasShuffle = reverseMapping != null;
            int hdrSize = opaddon.isa.Encoder.headerSize(pendingHandlers.size(), hasShuffle);
            // Shift all instruction offsets by header size
            for (int i = 0; i < offsets.length; i++) {
                offsets[i] += hdrSize;
            }

            // Patch branch instructions with final absolute offsets
            for (int i = 0; i < instructions.size(); i++) {
                Instruction insn = instructions.get(i);
                if (isBranch(insn.opcode())) {
                    int targetIdx = (int) insn.operand(0);
                    if (targetIdx >= 0 && targetIdx < offsets.length) {
                        instructions.set(i, new Instruction(insn.opcode(), offsets[targetIdx]));
                    }
                }
            }

            // Total size of instructions (for past-the-end labels)
            int totalInsnSize = 0;
            for (Instruction insn : instructions) {
                totalInsnSize += encodedSize(insn);
            }
            int pastEndOffset = hdrSize + totalInsnSize;

            // Resolve exception handlers
            for (Object[] pending : pendingHandlers) {
                LabelNode startLabel = (LabelNode) pending[0];
                LabelNode endLabel = (LabelNode) pending[1];
                LabelNode handlerLabel = (LabelNode) pending[2];
                int typeIdx = (Integer) pending[3];

                int startIdx = labelIndex(startLabel);
                int endIdx = labelIndex(endLabel);
                int handlerIdx = labelIndex(handlerLabel);

                exceptionHandlers.add(new int[]{
                    startIdx < offsets.length ? offsets[startIdx] : pastEndOffset,
                    endIdx < offsets.length ? offsets[endIdx] : pastEndOffset,
                    handlerIdx < offsets.length ? offsets[handlerIdx] : pastEndOffset,
                    typeIdx
                });
            }
        }

        private int[] computeOffsets() {
            int[] offsets = new int[instructions.size()];
            int offset = 0;
            for (int i = 0; i < instructions.size(); i++) {
                offsets[i] = offset;
                offset += encodedSize(instructions.get(i));
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

    // Small utility for readable opcode names in errors
    private static final class OpcodesUtil {
        static String opcodeName(int opcode) {
            try {
                for (java.lang.reflect.Field f : Opcodes.class.getFields()) {
                    if (f.getType() == int.class && f.getInt(null) == opcode) {
                        return f.getName();
                    }
                }
            } catch (Exception ignored) {}
            return "0x" + Integer.toHexString(opcode);
        }
    }
}
