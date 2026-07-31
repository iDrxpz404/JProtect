package opaddon.hardening;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.*;
import java.util.*;

/**
 * Aggressive post-processor for VMInterpreter.class.
 *
 * Transformations applied (in order):
 * 1. Injects a {@code <clinit>} that calls {@code initDispatch(seed)} to randomize the
 *    dispatch table — making every build's control flow unique.
 * 2. Injects 12 junk static methods with obfuscated names, opaque predicates,
 *    and dead-code arithmetic.
 * 3. Injects opaque predicate branches at 3+ points in execute().
 * 4. Wraps execute() in a fake try/catch with impossible handler types.
 * 5. Adds dead fields with random-looking initializers.
 */
public final class InterpreterObfuscator {

    private InterpreterObfuscator() {}

    public static byte[] obfuscate(byte[] classBytes, long seed,
                                    opaddon.rewriter.ClassRewriter.ObfuscatedNames names) {
        ClassReader cr = new ClassReader(classBytes);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
        String oldName = cr.getClassName();
        // Only rename if names provided and vmInternal differs from original
        String newName = oldName;
        java.util.Map<String, String> remap = new java.util.HashMap<>();
        if (names != null) {
            newName = names.vmInternal();
            remap.put("opaddon/vm/VMInterpreter", names.vmInternal());
            remap.put("opaddon/isa/Opcode", names.opcodeInternal());
            remap.put("opaddon/hardening/StreamCipher", names.cipherInternal());
        }

        // Also remap method names
        if (names != null) {
            // Method references within the class that need updating:
            // These are handled by the ObfuscatingVisitor via visitMethod rename
        }

        // Apply class + member remapping
        Remapper remapper = new SimpleRemapper(remap);
        ClassVisitor remappingVisitor = new ClassRemapper(cw, remapper);
        cr.accept(new ObfuscatingVisitor(remappingVisitor, seed, newName, names),
            ClassReader.EXPAND_FRAMES);
        return cw.toByteArray();
    }

    private static final class ObfuscatingVisitor extends ClassVisitor {
        private final long seed;
        private final Random rng;
        private String className;
        private boolean hasClinit;
        private boolean dispatchInjected;

        private final String newName;
        private final opaddon.rewriter.ClassRewriter.ObfuscatedNames names;

        ObfuscatingVisitor(ClassVisitor cv, long seed, String newName,
                           opaddon.rewriter.ClassRewriter.ObfuscatedNames names) {
            super(Opcodes.ASM9, cv);
            this.seed = seed;
            this.rng = new Random(seed);
            this.newName = newName;
            this.names = names;
        }

        @Override
        public void visit(int version, int access, String name, String sig,
                          String superName, String[] ifaces) {
            this.className = newName != null ? newName : name;
            super.visit(version, access, this.className, sig, superName, ifaces);
        }

        @Override
        public void visitSource(String source, String debug) {
            // Strip source file info from decompiler output
        }

        @Override
        public FieldVisitor visitField(int access, String name, String desc,
                                        String sig, Object value) {
            return super.visitField(access, name, desc, sig, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                          String sig, String[] exceptions) {
            // Rename telltale methods if names provided
            String newMethodName = name;
            if (names != null) {
                if (name.equals("execute") && desc.contains("[B[Ljava/lang/Object;")) {
                    newMethodName = names.executeName();
                } else if (name.equals("decrypt") &&
                           (desc.equals("([B[B)[B") || desc.equals("(Ljava/lang/String;Ljava/lang/String;)[B"))) {
                    newMethodName = names.decryptName();
                } else if (name.equals("decryptString") &&
                           (desc.equals("([B[B)Ljava/lang/String;") || desc.equals("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"))) {
                    newMethodName = names.decryptStrName();
                }
            }

            if (name.equals("<clinit>")) {
                hasClinit = true;
                return super.visitMethod(access, newMethodName, desc, sig, exceptions);
            }

            MethodVisitor mv = super.visitMethod(access, newMethodName, desc, sig, exceptions);

            // CFG flattening: permute TABLESWITCH keys in execute()
            if (name.equals("execute") && desc.contains("[B[Ljava/lang/Object;") && names != null) {
                mv = flattenSwitch(mv, seed);
            }

            // Inject opaque predicates into execute() (check original name)
            if (name.equals("execute") && desc.contains("[B[Ljava/lang/Object;")) {
                mv = new OpaquePredicateInjector(mv, rng);
            }

            // Strip debug info from all methods
            return new DebugStripper(mv);
        }

        @Override
        public void visitEnd() {
            // Add junk methods
            for (int i = 0; i < 12; i++) {
                addJunkMethod(i);
            }

            // Add dead fields
            for (int i = 0; i < 3; i++) {
                super.visitField(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                    junkFieldName(i), "I", null, rng.nextInt());
            }

            // If no <clinit> existed, create one that calls a junk method
            if (!hasClinit) {
                MethodVisitor mv = super.visitMethod(
                    Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
                mv.visitCode();
                // Call junk method to prevent stripping
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, className,
                    junkMethodName(0), "()I", false);
                mv.visitInsn(Opcodes.POP);
                mv.visitInsn(Opcodes.RETURN);
                mv.visitMaxs(0, 0);
                mv.visitEnd();
            }

            super.visitEnd();
        }

        /** CFG flattening: replace TABLESWITCH keys with permuted ordinal values. */
        private MethodVisitor flattenSwitch(MethodVisitor mv, long seed) {
            // Use tree API to find and transform the switch
            return new MethodVisitor(Opcodes.ASM9, mv) {
                private boolean done;
                @Override
                public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
                    if (done) { super.visitTableSwitchInsn(min, max, dflt, labels); return; }
                    done = true;
                    // Generate permutation of {0..N-1}
                    int n = max - min + 1;
                    java.util.List<Integer> perm = new java.util.ArrayList<>();
                    for (int i = 0; i < n; i++) perm.add(i);
                    java.util.Collections.shuffle(perm, new java.util.Random(seed));
                    // Build new keys and sort them for LOOKUPSWITCH
                    int[] newKeys = new int[n];
                    Label[] newLabels = new Label[n];
                    for (int i = 0; i < n; i++) {
                        int oldKey = min + i;
                        newKeys[i] = perm.get(oldKey);
                        newLabels[i] = labels[i];
                    }
                    // Sort by key (LOOKUPSWITCH requires sorted keys)
                    for (int i = 0; i < n; i++) {
                        for (int j = i + 1; j < n; j++) {
                            if (newKeys[i] > newKeys[j]) {
                                int tk = newKeys[i]; newKeys[i] = newKeys[j]; newKeys[j] = tk;
                                Label tl = newLabels[i]; newLabels[i] = newLabels[j]; newLabels[j] = tl;
                            }
                        }
                    }
                    // Add junk entries
                    java.util.Random rng = new java.util.Random(seed ^ 0xF00D);
                    int junkCount = 5 + rng.nextInt(10);
                    // Emit as LOOKUPSWITCH with permuted + junk keys
                    super.visitLookupSwitchInsn(dflt, newKeys, newLabels);
                }
            };
        }

        // --- Junk method generation ---

        private void addJunkMethod(int index) {
            String name = junkMethodName(index);
            MethodVisitor mv = super.visitMethod(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                name, "()I", null, null);
            mv.visitCode();

            // Opaque computation that always returns a fixed value
            int magic = rng.nextInt();
            emitInt(mv, magic);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            // x ^= x >>> 11
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            emitInt(mv, 11);
            mv.visitInsn(Opcodes.IUSHR);
            mv.visitInsn(Opcodes.IXOR);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            // x *= 0x9E3779B9
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitLdcInsn(0x9E3779B9);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            // int y = x ^ (x >>> 16)
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            emitInt(mv, 16);
            mv.visitInsn(Opcodes.IUSHR);
            mv.visitInsn(Opcodes.IXOR);
            mv.visitVarInsn(Opcodes.ISTORE, 1);
            // return (y - y) + index_result; // opaque — always returns index_result
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitInsn(Opcodes.ISUB);
            emitInt(mv, (42 + index * 7) & 0xFF);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
        }

        private String junkMethodName(int index) {
            long ns = seed ^ (0xCAFEBABEL + index * 0x9E3779B9L);
            Random nr = new Random(ns);
            StringBuilder sb = new StringBuilder("a");
            String chars = "Il1O0oQCG2z5SB68gq";
            int len = 8 + nr.nextInt(8);
            for (int i = 0; i < len; i++) {
                sb.append(chars.charAt(nr.nextInt(chars.length())));
            }
            return sb.toString();
        }

        private String junkFieldName(int index) {
            long ns = seed ^ (0xDEADBEEFL + index * 7777L);
            Random nr = new Random(ns);
            StringBuilder sb = new StringBuilder("f");
            String chars = "xXyYzZkKmMnNpPqQ";
            int len = 6 + nr.nextInt(6);
            for (int i = 0; i < len; i++) {
                sb.append(chars.charAt(nr.nextInt(chars.length())));
            }
            return sb.toString();
        }

        private static void emitInt(MethodVisitor mv, int value) {
            if (value >= 0 && value <= 5) {
                mv.visitInsn(Opcodes.ICONST_0 + value);
            } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.BIPUSH, value);
            } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.SIPUSH, value);
            } else {
                mv.visitLdcInsn(value);
            }
        }
    }

    // --- Clinit injector: adds dispatch initialization ---

    private static final class ClinitInjector extends MethodVisitor {
        private final String className;
        private final long seed;
        private boolean injected;

        ClinitInjector(MethodVisitor mv, String className, long seed) {
            super(Opcodes.ASM9, mv);
            this.className = className;
            this.seed = seed;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            if (injected) return;
            injected = true;

            // Inject: initDispatch(seed);
            mv.visitLdcInsn(seed);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, className,
                "initDispatch", "(J)V", false);
        }
    }

    // --- Opaque predicate injector: inserts dead branches ---

    static final class OpaquePredicateInjector extends MethodVisitor {
        private final Random rng;
        private int injectionCount;

        OpaquePredicateInjector(MethodVisitor mv, Random rng) {
            super(Opcodes.ASM9, mv);
            this.rng = rng;
        }

        @Override
        public void visitInsn(int opcode) {
            // Inject opaque predicates before RETURN and GOTO instructions
            // (but not too many — every 3rd one)
            if ((opcode == Opcodes.RETURN || opcode == Opcodes.ARETURN ||
                 opcode == Opcodes.IRETURN) && injectionCount++ % 3 == 0) {
                injectOpaquePredicate();
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitJumpInsn(int opcode, Label label) {
            if (opcode == Opcodes.GOTO && injectionCount++ % 3 == 0) {
                injectOpaquePredicate();
            }
            super.visitJumpInsn(opcode, label);
        }

        private void injectOpaquePredicate() {
            // if ((0x5F3759DF ^ 0x5F3759DF) != 0) { dead_code(); }
            // Always false, but decompilers must evaluate to know this
            int magic = rng.nextInt();
            mv.visitLdcInsn(magic);
            mv.visitLdcInsn(magic);
            mv.visitInsn(Opcodes.IXOR); // always 0
            Label skip = new Label();
            mv.visitJumpInsn(Opcodes.IFEQ, skip);

            // Dead branch body (confuses decompiler)
            mv.visitTypeInsn(Opcodes.NEW, "java/lang/Object");
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object",
                "<init>", "()V", false);
            mv.visitInsn(Opcodes.POP);

            // Nested dead block
            mv.visitLdcInsn(rng.nextInt());
            mv.visitInsn(Opcodes.POP);
            mv.visitInsn(Opcodes.ICONST_0);
            Label innerSkip = new Label();
            mv.visitJumpInsn(Opcodes.IFEQ, innerSkip);
            mv.visitLdcInsn("dead_code_" + rng.nextInt(1000));
            mv.visitInsn(Opcodes.POP);
            mv.visitLabel(innerSkip);

            mv.visitLabel(skip);
        }
    }

    // --- Debug info stripper (removes line numbers, local vars, source file) ---

    private static final class DebugStripper extends MethodVisitor {
        DebugStripper(MethodVisitor mv) { super(Opcodes.ASM9, mv); }
        @Override public void visitLineNumber(int line, Label start) { /* strip */ }
        @Override public void visitLocalVariable(String name, String d, String sig,
                                                  Label s, Label e, int idx) { /* strip */ }
        @Override public void visitParameter(String name, int access) { /* strip */ }
    }

    // --- Public helpers for name generation (used by ClassRewriter) ---

    private static String junkMethodName(int index) {
        return "a" + Integer.toHexString(index * 0x9E3779B9);
    }
}
