package opaddon.translator;

import opaddon.vm.VMInterpreter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests translation of branch and loop constructs.
 */
class BranchLoopTranslatorTest {

    private static ClassNode branchClass;
    private static ClassNode loopClass;
    private static final Object DUMMY_THIS = new Object();

    @BeforeAll
    static void loadTestClasses() throws Exception {
        branchClass = loadClass("opaddon/e2e/samples/BranchSample.class");
        loopClass = loadClass("opaddon/e2e/samples/LoopSample.class");
    }

    private static ClassNode loadClass(String path) throws Exception {
        try (InputStream is = BranchLoopTranslatorTest.class.getClassLoader()
                .getResourceAsStream(path)) {
            ClassReader cr = new ClassReader(is);
            ClassNode cn = new ClassNode();
            cr.accept(cn, ClassReader.EXPAND_FRAMES);
            return cn;
        }
    }

    private static MethodNode findMethod(ClassNode cn, String name) {
        for (MethodNode m : cn.methods) {
            if (m.name.equals(name)) return m;
        }
        throw new AssertionError("Method not found: " + name);
    }

    private static Object execute(MethodNode method, MethodTranslator.TranslationResult result,
                                   Object... args) {
        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        Object[] locals = new Object[method.maxLocals + 10];
        int slot = 0;
        if (!isStatic) locals[slot++] = DUMMY_THIS;
        int argIdx = 0;
        String desc = method.desc;
        int i = 1;
        while (desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == 'J' || c == 'D') {
                locals[slot] = args[argIdx++]; slot += 2; i++;
            } else if (c == 'L') {
                locals[slot++] = args[argIdx++];
                i = desc.indexOf(';', i) + 1;
            } else if (c == '[') {
                locals[slot++] = args[argIdx++];
                i++; while (i < desc.length() && desc.charAt(i) == '[') i++;
                if (i < desc.length() && desc.charAt(i) == 'L') i = desc.indexOf(';', i) + 1;
                else i++;
            } else { locals[slot++] = args[argIdx++]; i++; }
        }
        return VMInterpreter.execute(result.program(), result.constants(), locals);
    }

    // --- Branch tests ---

    @Test
    void max() {
        MethodNode m = findMethod(branchClass, "max");
        MethodTranslator.TranslationResult r = MethodTranslator.translate(m);
        assertEquals(5, execute(m, r, 3, 5));
        assertEquals(7, execute(m, r, 7, 2));
        assertEquals(0, execute(m, r, 0, 0));
    }

    @Test
    void sign() {
        MethodNode m = findMethod(branchClass, "sign");
        MethodTranslator.TranslationResult r = MethodTranslator.translate(m);
        assertEquals(1, execute(m, r, 5));
        assertEquals(-1, execute(m, r, -3));
        assertEquals(0, execute(m, r, 0));
    }

    @Test
    void grade() {
        MethodNode m = findMethod(branchClass, "grade");
        MethodTranslator.TranslationResult r = MethodTranslator.translate(m);
        // Note: String constants via LDC
        assertEquals("A", execute(m, r, 95));
        assertEquals("B", execute(m, r, 85));
        assertEquals("C", execute(m, r, 75));
        assertEquals("F", execute(m, r, 50));
    }

    @Test
    void inRange() {
        MethodNode m = findMethod(branchClass, "inRange");
        MethodTranslator.TranslationResult r = MethodTranslator.translate(m);
        assertEquals(1, execute(m, r, 5, 0, 10));
        assertEquals(0, execute(m, r, -1, 0, 10));
        assertEquals(0, execute(m, r, 15, 0, 10));
    }

    // --- Loop tests ---

    @Test
    void sumToN() {
        MethodNode m = findMethod(loopClass, "sumToN");
        MethodTranslator.TranslationResult r = MethodTranslator.translate(m);
        assertEquals(15, execute(m, r, 5));    // 1+2+3+4+5
        assertEquals(55, execute(m, r, 10));   // 1+...+10
        assertEquals(0, execute(m, r, 0));
    }

    @Test
    void factorial() {
        MethodNode m = findMethod(loopClass, "factorial");
        MethodTranslator.TranslationResult r = MethodTranslator.translate(m);
        assertEquals(120, execute(m, r, 5));
        assertEquals(1, execute(m, r, 0));
        assertEquals(1, execute(m, r, 1));
    }

    @Test
    void gcd() {
        MethodNode m = findMethod(loopClass, "gcd");
        MethodTranslator.TranslationResult r = MethodTranslator.translate(m);
        assertEquals(6, execute(m, r, 12, 18));
        assertEquals(1, execute(m, r, 17, 13));
        assertEquals(7, execute(m, r, 7, 0));
    }
}
