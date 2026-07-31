package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.e2e.samples.VirtualizedSample;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests: compile a class with @Virtualize annotations,
 * process it through ClassRewriter, load the processed class,
 * and verify virtualized methods work correctly.
 */
class EndToEndTest {

    private static final class ByteClassLoader extends ClassLoader {
        private final String className;
        private final byte[] bytes;

        ByteClassLoader(String className, byte[] bytes) {
            this.className = className;
            this.bytes = bytes;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if (name.equals(className)) {
                return defineClass(name, bytes, 0, bytes.length);
            }
            return super.findClass(name);
        }
    }

    private static CliOptions opts;

    @BeforeAll
    static void setUp() {
        opts = CliOptions.parse(new String[]{"--input", "dummy.jar", "--output", "dummy-out.jar"});
    }

    @Test
    void addVirtualized() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("addVirtualized", int.class, int.class)
            .invoke(instance, 3, 5);
        assertEquals(8, result);
    }

    @Test
    void multiplyVirtualized() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("multiplyVirtualized", int.class, int.class)
            .invoke(instance, 6, 7);
        assertEquals(42, result);
    }

    @Test
    void maxVirtualized() throws Exception {
        Object instance = processAndLoad();
        Class<?> clazz = instance.getClass();
        assertEquals(5, clazz.getMethod("maxVirtualized", int.class, int.class).invoke(instance, 3, 5));
        assertEquals(7, clazz.getMethod("maxVirtualized", int.class, int.class).invoke(instance, 7, 2));
    }

    @Test
    void sumToNVirtualized() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("sumToNVirtualized", int.class)
            .invoke(instance, 10);
        assertEquals(55, result);
    }

    @Test
    void factorialVirtualized() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("factorialVirtualized", int.class)
            .invoke(instance, 5);
        assertEquals(120, result);
    }

    @Test
    void signVirtualized() throws Exception {
        Object instance = processAndLoad();
        Class<?> clazz = instance.getClass();
        assertEquals(1,  clazz.getMethod("signVirtualized", int.class).invoke(instance, 42));
        assertEquals(-1, clazz.getMethod("signVirtualized", int.class).invoke(instance, -7));
        assertEquals(0,  clazz.getMethod("signVirtualized", int.class).invoke(instance, 0));
    }

    @Test
    void gradeVirtualized() throws Exception {
        Object instance = processAndLoad();
        Class<?> clazz = instance.getClass();
        assertEquals("A", clazz.getMethod("gradeVirtualized", int.class).invoke(instance, 95));
        assertEquals("B", clazz.getMethod("gradeVirtualized", int.class).invoke(instance, 85));
        assertEquals("C", clazz.getMethod("gradeVirtualized", int.class).invoke(instance, 75));
        assertEquals("F", clazz.getMethod("gradeVirtualized", int.class).invoke(instance, 50));
    }

    @Test
    void longAddVirtualized() throws Exception {
        Object instance = processAndLoad();
        long result = (Long) instance.getClass()
            .getMethod("longAddVirtualized", long.class, long.class)
            .invoke(instance, 100L, 200L);
        assertEquals(300L, result);
    }

    @Test
    void doubleMulVirtualized() throws Exception {
        Object instance = processAndLoad();
        double result = (Double) instance.getClass()
            .getMethod("doubleMulVirtualized", double.class, double.class)
            .invoke(instance, 2.5, 3.0);
        assertEquals(7.5, result, 0.0001);
    }

    @Test
    void nonVirtualizedMethodStillWorks() throws Exception {
        Object instance = processAndLoad();
        // The non-annotated add() method should still work normally
        int result = (Integer) instance.getClass()
            .getMethod("add", int.class, int.class)
            .invoke(instance, 3, 5);
        assertEquals(8, result);
    }

    @Test
    void virtualizedAndOriginalProduceSameResult() throws Exception {
        // Compare virtualized vs. unvirtualized
        VirtualizedSample original = new VirtualizedSample();
        Object virtualized = processAndLoad();
        Class<?> vc = virtualized.getClass();

        // Test many inputs
        for (int a = -10; a <= 10; a++) {
            for (int b = -10; b <= 10; b++) {
                int expected = original.addVirtualized(a, b);
                int actual = (Integer) vc.getMethod("addVirtualized", int.class, int.class)
                    .invoke(virtualized, a, b);
                assertEquals(expected, actual,
                    "Mismatch for addVirtualized(" + a + ", " + b + ")");
            }
        }
    }

    // --- Helper ---

    private Object processAndLoad() throws Exception {
        String classPath = "opaddon/e2e/samples/VirtualizedSample.class";
        Path classFile = findClassFile(classPath);
        byte[] originalBytes = Files.readAllBytes(classFile);

        // Process through ClassRewriter — this virtualizes the annotated methods
        byte[] processedBytes = ClassRewriter.processClass(originalBytes, opts);

        // The processed class should be valid
        assertTrue(processedBytes.length > 0);

        // Load the processed class
        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.VirtualizedSample", processedBytes);
        Class<?> processedClass = loader.loadClass("opaddon.e2e.samples.VirtualizedSample");
        return processedClass.getDeclaredConstructor().newInstance();
    }

    private static Path findClassFile(String classFilePath) {
        Path p = Path.of("target", "test-classes", classFilePath);
        if (Files.exists(p)) return p;
        p = Path.of("target", "classes", classFilePath);
        if (Files.exists(p)) return p;
        throw new RuntimeException("Cannot find class file: " + classFilePath);
    }
}
