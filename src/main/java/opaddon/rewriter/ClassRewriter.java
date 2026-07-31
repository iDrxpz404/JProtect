package opaddon.rewriter;

import opaddon.annotation.Virtualize;
import opaddon.cli.CliOptions;
import opaddon.config.IntegrityVerifier;
import opaddon.config.VirtualizerConfig;
import opaddon.hardening.NameGenerator;
import opaddon.translator.MethodTranslator;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * Reads a jar, processes each .class entry, and rewrites @Virtualize-annotated
 * methods into VM interpreter calls.
 */
public final class ClassRewriter {

    private ClassRewriter() {}

    /** Per-build obfuscated identifiers — hide VM telltale names. */
    public record ObfuscatedNames(
        String vmClassName,      // e.g., "a1B2c" instead of "opaddon/vm/VMInterpreter"
        String executeName,      // e.g., "l1I0O" instead of "execute"
        String decryptName,      // e.g., "Qz5B" instead of "decrypt"
        String decryptStrName    // e.g., "C2g8" instead of "decryptString"
    ) {
        public static ObfuscatedNames generate(long seed) {
            return new ObfuscatedNames(
                NameGenerator.className(seed),
                NameGenerator.methodName(seed ^ 0x1000L),
                NameGenerator.methodName(seed ^ 0x2000L),
                NameGenerator.methodName(seed ^ 0x3000L)
            );
        }

        /** Full internal name for INVOKESTATIC: e.g., "a1B2c" */
        public String vmInternal() { return vmClassName; }
        /** Method descriptor for execute: ([B[Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object; */
        public String executeDesc() { return "([B[Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"; }
        /** Method descriptor for decrypt: ([B[B)[B */
        public String decryptDesc() { return "([B[B)[B"; }
        /** Method descriptor for decryptString: ([B[B)Ljava/lang/String; */
        public String decryptStrDesc() { return "([B[B)Ljava/lang/String;"; }
    }

    public static byte[] processJar(CliOptions opts, VirtualizerConfig config, ObfuscatedNames names) throws Exception {
        Path inputPath = Path.of(opts.getInputPath());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (JarOutputStream jos = new JarOutputStream(out);
             JarInputStream jis = new JarInputStream(Files.newInputStream(inputPath))) {
            JarEntry entry;
            while ((entry = jis.getNextJarEntry()) != null) {
                byte[] data = jis.readAllBytes();
                if (entry.getName().endsWith(".class")) {
                    if (entry.getName().equals(names.vmInternal() + ".class") && config.isPolymorphicVM()) {
                        // VM stays in package
                        if (opts.isVerbose()) System.out.println("[virtualizer] Obfuscated VMInterpreter");
                    }
                    data = processClass(data, opts, config, names);
                }
                JarEntry outEntry = new JarEntry(entry.getName());
                jos.putNextEntry(outEntry);
                jos.write(data);
                jos.closeEntry();
            }
            // Inject junk classes to confuse decompilers
            injectJunkClasses(jos, names, opts.getSeed());
        }
        return out.toByteArray();
    }

    /** Inject random-looking empty classes into the output jar. */
    private static void injectJunkClasses(JarOutputStream jos, ObfuscatedNames names,
                                           long seed) throws Exception {
        java.util.Random rng = new java.util.Random(seed ^ 0xDEADBEEFL);
        int count = 3 + rng.nextInt(5);
        for (int i = 0; i < count; i++) {
            String junkName = opaddon.hardening.NameGenerator.className(
                seed ^ (0x10000L + i * 7777L));
            ClassWriter cw = new ClassWriter(0);
            cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC,
                junkName, null, "java/lang/Object", null);
            // Add a junk method
            MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "m", "()I", null, null);
            mv.visitCode();
            mv.visitLdcInsn(rng.nextInt());
            mv.visitInsn(Opcodes.IRETURN);
            mv.visitMaxs(1, 1);
            mv.visitEnd();
            cw.visitEnd();
            JarEntry je = new JarEntry(junkName + ".class");
            jos.putNextEntry(je);
            jos.write(cw.toByteArray());
            jos.closeEntry();
        }
    }

    /** Read VMInterpreter from classpath, obfuscate, rename, and add to jar. */
    private static void bundleVMRuntime(JarOutputStream jos, ObfuscatedNames names,
                                         CliOptions opts) throws Exception {
        String vmPath = "opaddon/vm/VMInterpreter.class";
        java.io.InputStream is = ClassRewriter.class.getClassLoader().getResourceAsStream(vmPath);
        if (is == null) {
            if (opts.isVerbose()) System.err.println("[virtualizer] WARN: VM class not found on classpath");
            return;
        }
        byte[] vmBytes = is.readAllBytes();
        is.close();
        vmBytes = opaddon.hardening.InterpreterObfuscator.obfuscate(vmBytes, opts.getSeed(), names);
        JarEntry vmEntry = new JarEntry(names.vmInternal() + ".class");
        jos.putNextEntry(vmEntry);
        jos.write(vmBytes);
        jos.closeEntry();
    }

    public static byte[] processClass(byte[] classBytes, CliOptions opts) {
        return processClass(classBytes, opts, VirtualizerConfig.defaults(), ObfuscatedNames.generate(0));
    }

    public static byte[] processClass(byte[] classBytes, CliOptions opts, VirtualizerConfig config, ObfuscatedNames names) {
        ClassReader cr = new ClassReader(classBytes);
        ClassNode cn = new ClassNode();
        cr.accept(cn, ClassReader.EXPAND_FRAMES);

        // Pre-scan: translate all @Virtualize methods
        List<ProtectedMethod> protectedMethods = new ArrayList<>();
        for (MethodNode m : cn.methods) {
            if ((hasVirtualizeAnnotation(m) ||
                (config.matchesVirtualize(cn.name) && !config.matchesExclude(cn.name))) &&
                !m.name.equals("<init>") && !m.name.equals("<clinit>")) {
                if (containsInvokeDynamic(m)) {
                    System.err.println("[virtualizer] WARNING: " + cn.name + "." + m.name +
                        " contains invokedynamic — skipping (not supported yet)");
                    continue;
                }
                MethodTranslator.TranslationResult result = MethodTranslator.translate(m, opts.getSeed());
                protectedMethods.add(new ProtectedMethod(m, result, opts.getSeed(), cn.name, config));
            }
        }

        if (protectedMethods.isEmpty()) {
            return classBytes;
        }

        if (opts.isVerbose()) {
            System.out.println("[virtualizer] Protecting " + cn.name + " (" +
                protectedMethods.size() + " method(s))");
        }

        // Build output class — use ClassReader.accept() to preserve constant pool
        // indices for non-virtualized methods (bypasses tree API)
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
        ClassReader cr2 = new ClassReader(classBytes);
        cr2.accept(new RewritingClassVisitor(cw, cn, protectedMethods, names), ClassReader.EXPAND_FRAMES);
        return cw.toByteArray();
    }

    private static boolean containsInvokeDynamic(MethodNode m) {
        for (AbstractInsnNode insn : m.instructions) {
            if (insn.getType() == AbstractInsnNode.INVOKE_DYNAMIC_INSN) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasVirtualizeAnnotation(MethodNode m) {
        if (m.invisibleAnnotations == null) return false;
        for (AnnotationNode ann : m.invisibleAnnotations) {
            if (ann.desc.equals(Type.getDescriptor(Virtualize.class))) {
                return true;
            }
        }
        return false;
    }

    // --- Data holder ---

    private static final class ProtectedMethod {
        final MethodNode method;
        final byte[] program;
        final byte[] encryptedProgram;
        final byte[] key;
        final Object[] constants;
        final byte[][] encryptedStrings; // XOR-encrypted string values (or null if not a string)
        final String programField;
        final String constantsField;

        ProtectedMethod(MethodNode method, MethodTranslator.TranslationResult result,
                        long seed, String className, VirtualizerConfig config) {
            this.method = method;
            byte[] plain = result.program();
            this.program = plain;
            this.constants = result.constants();
            // Obfuscated field names — CFR won't see "PROGRAM_0"
            this.programField = opaddon.hardening.NameGenerator.fieldName(
                seed ^ (0x5000L + nextId()));
            this.constantsField = opaddon.hardening.NameGenerator.fieldName(
                seed ^ (0x6000L + nextId()));

            // AES-256-GCM authenticated encryption
            opaddon.hardening.StreamCipher.EncryptResult encResult =
                opaddon.hardening.StreamCipher.encrypt(seed, className, plain);
            this.encryptedProgram = encResult.encrypted();
            this.key = encResult.keyBytes();

            // Encrypt string constants (but NOT class names / descriptors)
            this.encryptedStrings = new byte[constants.length][];
            if (seed != 0 && config.isStringEncryption()) {
                for (int i = 0; i < constants.length; i++) {
                    if (constants[i] instanceof String) {
                        String s = (String) constants[i];
                        // Skip class names (contain '/') and descriptors
                        if (s.indexOf('/') >= 0 || s.startsWith("(")) continue;
                        byte[] strBytes = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        // XOR with program key for string encryption
                        byte[] strEnc = new byte[strBytes.length];
                        for (int j = 0; j < strBytes.length; j++)
                            strEnc[j] = (byte)(strBytes[j] ^ this.key[j % this.key.length]);
                        encryptedStrings[i] = strEnc;
                    }
                }
            }
        }

        private static int idCounter;
        private static synchronized int nextId() { return idCounter++; }
    }

    // --- Rewriting visitor ---

    private static final class RewritingClassVisitor extends ClassVisitor {
        private final ClassNode original;
        private final List<ProtectedMethod> protectedMethods;
        private final Set<String> virtualizedKeys;
        private final ObfuscatedNames names;
        private String className;
        private boolean fieldsAdded;
        private boolean hasClinit;

        RewritingClassVisitor(ClassWriter cw, ClassNode original,
                              List<ProtectedMethod> protectedMethods,
                              ObfuscatedNames names) {
            super(Opcodes.ASM9, cw);
            this.original = original;
            this.names = names;
            this.protectedMethods = protectedMethods;
            this.virtualizedKeys = new HashSet<>();
            for (ProtectedMethod pm : protectedMethods) {
                virtualizedKeys.add(pm.method.name + pm.method.desc);
            }
            for (MethodNode m : original.methods) {
                if (m.name.equals("<clinit>")) { hasClinit = true; break; }
            }
        }

        @Override
        public void visitSource(String source, String debug) {
            // Strip source file info from decompiled output
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            this.className = name;
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor,
                                        String signature, Object value) {
            // Add our program/constants fields before the first existing field
            if (!fieldsAdded) {
                addVirtualizerFields();
            }
            return super.visitField(access, name, descriptor, signature, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                          String signature, String[] exceptions) {
            // Add fields if no fields existed (visitField was never called)
            if (!fieldsAdded) {
                addVirtualizerFields();
            }

            String key = name + descriptor;

            if (virtualizedKeys.contains(key)) {
                // Never virtualize constructors or static initializers
                if (name.equals("<init>") || name.equals("<clinit>")) {
                    return super.visitMethod(access, name, descriptor, signature, exceptions);
                }
                ProtectedMethod pm = findProtected(name, descriptor);
                return rewriteMethod(access, name, descriptor, signature, exceptions, pm);
            }

            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

            // Augment <clinit> to initialize our fields
            if (name.equals("<clinit>")) {
                hasClinit = true;
                return new ClinitInitVisitor(mv, className, protectedMethods, names);
            }

            return mv;
        }

        @Override
        public void visitEnd() {
            if (!fieldsAdded) {
                addVirtualizerFields();
            }
            // If the class has no <clinit> and we have protected methods,
            // create a <clinit> that initializes our fields
            if (!protectedMethods.isEmpty() && !hasClinit) {
                MethodVisitor mv = super.visitMethod(
                    Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
                mv.visitCode();
                // Emit init code for all protected methods
                for (ProtectedMethod pm : protectedMethods) {
                    emitByteArrayInit(mv, className, pm);
                    emitConstantsInit(mv, className, pm);
                }
                mv.visitInsn(Opcodes.RETURN);
                mv.visitMaxs(0, 0);
                mv.visitEnd();
            }
            super.visitEnd();
        }

        // --- clinit emission (shared between existing and new <clinit>) ---

        private void emitByteArrayInit(MethodVisitor mv, String owner, ProtectedMethod pm) {
            // Compact: Base64-encode both encrypted data and key as strings
            String encB64 = java.util.Base64.getEncoder().encodeToString(pm.encryptedProgram);
            String keyB64 = java.util.Base64.getEncoder().encodeToString(pm.key);
            mv.visitLdcInsn(encB64);
            mv.visitLdcInsn(keyB64);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "opaddon/vm/VMInterpreter", "decrypt",
                "(Ljava/lang/String;Ljava/lang/String;)[B", false);
            mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, pm.programField, "[B");
        }

        private void emitConstantsInit(MethodVisitor mv, String owner, ProtectedMethod pm) {
            Object[] constants = pm.constants;
            byte[][] encryptedStrings = pm.encryptedStrings;
            byte[] programKey = pm.key;

            emitInt(mv, constants.length);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            for (int j = 0; j < constants.length; j++) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, j);
                if (encryptedStrings[j] != null) {
                    emitEncryptedString(mv, encryptedStrings[j], programKey);
                } else {
                    emitConstant(mv, constants[j]);
                }
                mv.visitInsn(Opcodes.AASTORE);
            }
            mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, pm.constantsField, "[Ljava/lang/Object;");
        }

        private void emitEncryptedString(MethodVisitor mv, byte[] encrypted, byte[] key) {
            emitInt(mv, encrypted.length);
            mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            for (int j = 0; j < encrypted.length; j++) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, j);
                emitInt(mv, encrypted[j]);
                mv.visitInsn(Opcodes.BASTORE);
            }
            emitInt(mv, key.length);
            mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            for (int j = 0; j < key.length; j++) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, j);
                emitInt(mv, key[j]);
                mv.visitInsn(Opcodes.BASTORE);
            }
            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "opaddon/vm/VMInterpreter", "decryptString", "([B[B)Ljava/lang/String;", false);
        }

        private void emitConstant(MethodVisitor mv, Object value) {
            if (value == null) {
                mv.visitInsn(Opcodes.ACONST_NULL);
            } else if (value instanceof Integer) {
                emitInt(mv, (Integer) value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "valueOf", "(I)Ljava/lang/Integer;", false);
            } else if (value instanceof Long) {
                mv.visitLdcInsn(value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "valueOf", "(J)Ljava/lang/Long;", false);
            } else if (value instanceof Float) {
                mv.visitLdcInsn(value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float",
                    "valueOf", "(F)Ljava/lang/Float;", false);
            } else if (value instanceof Double) {
                mv.visitLdcInsn(value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double",
                    "valueOf", "(D)Ljava/lang/Double;", false);
            } else if (value instanceof String) {
                mv.visitLdcInsn(value);
            } else if (value instanceof Type) {
                mv.visitLdcInsn(value);
            } else if (value instanceof String[]) {
                String[] arr = (String[]) value;
                emitInt(mv, arr.length);
                mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
                for (int j = 0; j < arr.length; j++) {
                    mv.visitInsn(Opcodes.DUP);
                    emitInt(mv, j);
                    mv.visitLdcInsn(arr[j]);
                    mv.visitInsn(Opcodes.AASTORE);
                }
            } else {
                throw new UnsupportedOperationException(
                    "Unsupported constant type: " + value.getClass().getName());
            }
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

        private void addVirtualizerFields() {
            fieldsAdded = true;
            for (ProtectedMethod pm : protectedMethods) {
                super.visitField(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                    pm.programField, "[B", null, null);
                super.visitField(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                    pm.constantsField, "[Ljava/lang/Object;", null, null);
            }
        }

        private ProtectedMethod findProtected(String name, String desc) {
            for (ProtectedMethod pm : protectedMethods) {
                if (pm.method.name.equals(name) && pm.method.desc.equals(desc)) return pm;
            }
            throw new IllegalStateException("Protected method not found: " + name + desc);
        }

        // --- Method rewriting ---

        private MethodVisitor rewriteMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions,
                                             ProtectedMethod pm) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            mv.visitCode();

            // Load program byte[]
            mv.visitFieldInsn(Opcodes.GETSTATIC, className, pm.programField, "[B");

            // Load constants Object[]
            mv.visitFieldInsn(Opcodes.GETSTATIC, className, pm.constantsField, "[Ljava/lang/Object;");

            // Build args array
            Type[] argTypes = Type.getArgumentTypes(descriptor);
            boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
            int argCount = isStatic ? argTypes.length : argTypes.length + 1;

            emitInt(mv, argCount);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");

            int localSlot = 0;
            int arrIdx = 0;

            if (!isStatic) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, arrIdx++);
                mv.visitVarInsn(Opcodes.ALOAD, 0);
                mv.visitInsn(Opcodes.AASTORE);
                localSlot = 1;
            }

            for (Type argType : argTypes) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, arrIdx++);
                loadArg(mv, argType, localSlot);
                boxIfNeeded(mv, argType);
                mv.visitInsn(Opcodes.AASTORE);
                localSlot += argType.getSize();
            }

            // Call VMInterpreter
            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "opaddon/vm/VMInterpreter", "execute",
                "([B[Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);

            // Unbox and return
            Type returnType = Type.getReturnType(descriptor);
            unboxAndReturn(mv, returnType);

            mv.visitMaxs(0, 0);
            mv.visitEnd();
            return null; // we handled the method, don't delegate further
        }

        private static void loadArg(MethodVisitor mv, Type type, int slot) {
            int sort = type.getSort();
            if (sort == Type.LONG) { mv.visitVarInsn(Opcodes.LLOAD, slot); }
            else if (sort == Type.FLOAT) { mv.visitVarInsn(Opcodes.FLOAD, slot); }
            else if (sort == Type.DOUBLE) { mv.visitVarInsn(Opcodes.DLOAD, slot); }
            else if (sort == Type.OBJECT || sort == Type.ARRAY) {
                mv.visitVarInsn(Opcodes.ALOAD, slot);
            } else { mv.visitVarInsn(Opcodes.ILOAD, slot); }
        }

        private static void boxIfNeeded(MethodVisitor mv, Type type) {
            switch (type.getSort()) {
                case Type.BOOLEAN:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Boolean",
                        "valueOf", "(Z)Ljava/lang/Boolean;", false); break;
                case Type.CHAR:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Character",
                        "valueOf", "(C)Ljava/lang/Character;", false); break;
                case Type.BYTE:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Byte",
                        "valueOf", "(B)Ljava/lang/Byte;", false); break;
                case Type.SHORT:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Short",
                        "valueOf", "(S)Ljava/lang/Short;", false); break;
                case Type.INT:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer",
                        "valueOf", "(I)Ljava/lang/Integer;", false); break;
                case Type.LONG:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long",
                        "valueOf", "(J)Ljava/lang/Long;", false); break;
                case Type.FLOAT:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float",
                        "valueOf", "(F)Ljava/lang/Float;", false); break;
                case Type.DOUBLE:
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double",
                        "valueOf", "(D)Ljava/lang/Double;", false); break;
                default: break; // objects don't need boxing
            }
        }

        private void unboxAndReturn(MethodVisitor mv, Type returnType) {
            switch (returnType.getSort()) {
                case Type.VOID:
                    mv.visitInsn(Opcodes.POP);
                    mv.visitInsn(Opcodes.RETURN);
                    break;
                case Type.BOOLEAN:
                    // JVM represents boolean as int (0=false, 1=true)
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Integer");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Integer",
                        "intValue", "()I", false);
                    // Convert int to boolean: push 0, compare !=
                    Label pushTrue = new Label();
                    Label end = new Label();
                    mv.visitInsn(Opcodes.DUP);
                    mv.visitJumpInsn(Opcodes.IFNE, pushTrue);
                    mv.visitInsn(Opcodes.POP);
                    mv.visitInsn(Opcodes.ICONST_0);
                    mv.visitJumpInsn(Opcodes.GOTO, end);
                    mv.visitLabel(pushTrue);
                    mv.visitInsn(Opcodes.POP);
                    mv.visitInsn(Opcodes.ICONST_1);
                    mv.visitLabel(end);
                    mv.visitInsn(Opcodes.IRETURN);
                    break;
                case Type.CHAR:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Character");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Character",
                        "charValue", "()C", false);
                    mv.visitInsn(Opcodes.IRETURN);
                    break;
                case Type.BYTE:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Byte");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Byte",
                        "byteValue", "()B", false);
                    mv.visitInsn(Opcodes.IRETURN);
                    break;
                case Type.SHORT:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Short");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Short",
                        "shortValue", "()S", false);
                    mv.visitInsn(Opcodes.IRETURN);
                    break;
                case Type.INT:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Integer");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Integer",
                        "intValue", "()I", false);
                    mv.visitInsn(Opcodes.IRETURN);
                    break;
                case Type.LONG:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Long");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Long",
                        "longValue", "()J", false);
                    mv.visitInsn(Opcodes.LRETURN);
                    break;
                case Type.FLOAT:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Float");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Float",
                        "floatValue", "()F", false);
                    mv.visitInsn(Opcodes.FRETURN);
                    break;
                case Type.DOUBLE:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Double");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Double",
                        "doubleValue", "()D", false);
                    mv.visitInsn(Opcodes.DRETURN);
                    break;
                default:
                    mv.visitTypeInsn(Opcodes.CHECKCAST, returnType.getInternalName());
                    mv.visitInsn(Opcodes.ARETURN);
                    break;
            }
        }
    }

    /**
     * Injects field initialization into {@code <clinit>}.
     */
    private static final class ClinitInitVisitor extends MethodVisitor {
        private final String className;
        private final List<ProtectedMethod> methods;
        private final ObfuscatedNames names;

        ClinitInitVisitor(MethodVisitor mv, String className, List<ProtectedMethod> methods, ObfuscatedNames names) {
            super(Opcodes.ASM9, mv);
            this.className = className;
            this.methods = methods;
            this.names = names;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Emit init code BEFORE the existing <clinit> body
            for (ProtectedMethod pm : methods) {
                emitByteArrayInit(pm);
                emitConstantsInit(pm);
            }
        }

        private void emitByteArrayInit(ProtectedMethod pm) {
            String encB64 = java.util.Base64.getEncoder().encodeToString(pm.encryptedProgram);
            String keyB64 = java.util.Base64.getEncoder().encodeToString(pm.key);
            mv.visitLdcInsn(encB64);
            mv.visitLdcInsn(keyB64);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "opaddon/vm/VMInterpreter", "decrypt",
                "(Ljava/lang/String;Ljava/lang/String;)[B", false);
            mv.visitFieldInsn(Opcodes.PUTSTATIC, className, pm.programField, "[B");
        }

        private void emitConstantsInit(ProtectedMethod pm) {
            Object[] constants = pm.constants;
            byte[][] encryptedStrings = pm.encryptedStrings;
            byte[] programKey = pm.key;

            emitInt(mv, constants.length);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            for (int j = 0; j < constants.length; j++) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, j);
                if (encryptedStrings[j] != null) {
                    // Emit encrypted string: create byte[], create key, call decryptString
                    emitEncryptedString(encryptedStrings[j], programKey);
                } else {
                    emitConstant(constants[j]);
                }
                mv.visitInsn(Opcodes.AASTORE);
            }
            mv.visitFieldInsn(Opcodes.PUTSTATIC, className, pm.constantsField, "[Ljava/lang/Object;");
        }

        /** Emit code that creates an encrypted byte array and decrypts it to a String. */
        private void emitEncryptedString(byte[] encrypted, byte[] key) {
            // Create encrypted byte array
            emitInt(mv, encrypted.length);
            mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            for (int j = 0; j < encrypted.length; j++) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, j);
                emitInt(mv, encrypted[j]);
                mv.visitInsn(Opcodes.BASTORE);
            }

            // Create key byte array (reuse program key)
            emitInt(mv, key.length);
            mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            for (int j = 0; j < key.length; j++) {
                mv.visitInsn(Opcodes.DUP);
                emitInt(mv, j);
                emitInt(mv, key[j]);
                mv.visitInsn(Opcodes.BASTORE);
            }

            // Call VMInterpreter.decryptString(enc, key) → String
            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "opaddon/vm/VMInterpreter", "decryptString",
                "([B[B)Ljava/lang/String;", false);
        }

        private void emitConstant(Object value) {
            if (value == null) {
                mv.visitInsn(Opcodes.ACONST_NULL);
            } else if (value instanceof Integer) {
                emitInt(mv, (Integer) value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "valueOf", "(I)Ljava/lang/Integer;", false);
            } else if (value instanceof Long) {
                mv.visitLdcInsn(value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "valueOf", "(J)Ljava/lang/Long;", false);
            } else if (value instanceof Float) {
                mv.visitLdcInsn(value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float",
                    "valueOf", "(F)Ljava/lang/Float;", false);
            } else if (value instanceof Double) {
                mv.visitLdcInsn(value);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double",
                    "valueOf", "(D)Ljava/lang/Double;", false);
            } else if (value instanceof String) {
                mv.visitLdcInsn(value);
            } else if (value instanceof Type) {
                mv.visitLdcInsn(value);
            } else if (value instanceof String[]) {
                String[] arr = (String[]) value;
                emitInt(mv, arr.length);
                mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
                for (int j = 0; j < arr.length; j++) {
                    mv.visitInsn(Opcodes.DUP);
                    emitInt(mv, j);
                    mv.visitLdcInsn(arr[j]);
                    mv.visitInsn(Opcodes.AASTORE);
                }
            } else {
                throw new UnsupportedOperationException(
                    "Unsupported constant type: " + value.getClass().getName());
            }
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
}
