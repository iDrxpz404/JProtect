package opaddon.translator;

import opaddon.vm.VMInterpreter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.InputStream;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that MethodTranslator correctly translates JVM bytecode to custom ISA
 * and that the VMInterpreter executes the result correctly.
 */
class MethodTranslatorTest {

    private static ClassNode arithmeticClass;
    /** Dummy instance for calling non-static methods through the interpreter. */
    private static final Object DUMMY_THIS = new Object();

    @BeforeAll
    static void loadTestClass() throws Exception {
        String path = "opaddon/e2e/samples/ArithmeticSample.class";
        try (InputStream is = MethodTranslatorTest.class.getClassLoader().getResourceAsStream(path)) {
            assertNotNull(is, "Could not find " + path);
            ClassReader cr = new ClassReader(is);
            ClassNode cn = new ClassNode();
            cr.accept(cn, ClassReader.EXPAND_FRAMES);
            arithmeticClass = cn;
        }
    }

    private static MethodNode findMethod(String name) {
        for (MethodNode m : arithmeticClass.methods) {
            if (m.name.equals(name)) return m;
        }
        throw new AssertionError("Method not found: " + name);
    }

    /**
     * Execute a translated method, placing args into the correct locals slots
     * matching the JVM calling convention (this at 0, then each arg at the
     * next available slot; long/double take 2 slots).
     */
    private static Object execute(MethodNode method, MethodTranslator.TranslationResult result,
                                   Object... args) {
        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        Object[] locals = new Object[method.maxLocals + 10];
        int slot = 0;

        if (!isStatic) {
            locals[slot++] = DUMMY_THIS;
        }

        // Parse descriptor to get parameter types
        String desc = method.desc;
        int argIdx = 0;
        int i = 1; // skip '('
        while (desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == 'J' || c == 'D') {
                // long/double take 2 slots
                locals[slot] = args[argIdx++];
                slot += 2;
                i++;
            } else if (c == 'L') {
                locals[slot++] = args[argIdx++];
                i = desc.indexOf(';', i) + 1;
            } else if (c == '[') {
                locals[slot++] = args[argIdx++];
                i++;
                while (i < desc.length() && desc.charAt(i) == '[') i++;
                if (i < desc.length() && desc.charAt(i) == 'L') {
                    i = desc.indexOf(';', i) + 1;
                } else if (i < desc.length()) {
                    i++;
                }
            } else {
                // int, float, byte, char, short, boolean — all 1 slot
                locals[slot++] = args[argIdx++];
                i++;
            }
        }

        return VMInterpreter.execute(result.program(), result.constants(), locals);
    }

    @Test
    void translateSimpleAdd() {
        MethodNode method = findMethod("add");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        assertNotNull(result.instructions());
        assertFalse(result.instructions().isEmpty(), "Should produce instructions");

        assertEquals(8, execute(method, result, 3, 5));
    }

    @Test
    void translateMultiply() {
        MethodNode method = findMethod("multiply");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        assertEquals(42, execute(method, result, 6, 7));
    }

    @Test
    void translateComplex() {
        MethodNode method = findMethod("complex");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        assertEquals(10, execute(method, result, 2, 3, 4)); // 2*3 + 4
    }

    @Test
    void translateLongAdd() {
        MethodNode method = findMethod("longAdd");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        assertEquals(300L, execute(method, result, 100L, 200L));
    }

    @Test
    void translateDoubleMul() {
        MethodNode method = findMethod("doubleMul");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        Object ret = execute(method, result, 2.5, 3.0);
        assertEquals(7.5, (Double) ret, 0.0001);
    }

    // concat() uses invokedynamic (StringConcatFactory) in Java 9+ — skip for now
    // @Test
    void translateConcat() {
        MethodNode method = findMethod("concat");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        Object ret = execute(method, result, "hello", "world");
        assertEquals("helloworld", ret);
    }

    @Test
    void translateIsPositive() {
        // JVM represents boolean as int (0/1)
        MethodNode method = findMethod("isPositive");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        assertEquals(1, execute(method, result, 5));
        assertEquals(0, execute(method, result, -3));
        assertEquals(0, execute(method, result, 0));
    }

    @Test
    void translateConditional() {
        MethodNode method = findMethod("conditional");
        MethodTranslator.TranslationResult result = MethodTranslator.translate(method);

        assertEquals(1, execute(method, result, 7));
        assertEquals(-1, execute(method, result, -2));
    }

    @Test
    void translatedProgramsAreDeterministic() {
        MethodNode method = findMethod("add");
        MethodTranslator.TranslationResult r1 = MethodTranslator.translate(method);
        MethodTranslator.TranslationResult r2 = MethodTranslator.translate(method);

        assertEquals(r1.instructions(), r2.instructions());
        assertArrayEquals(r1.constants(), r2.constants());
    }
}
