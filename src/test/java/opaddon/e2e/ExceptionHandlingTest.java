package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that virtualized methods with try/catch blocks work correctly.
 */
class ExceptionHandlingTest {

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
    void safeDivideNormal() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("safeDivide", int.class, int.class)
            .invoke(instance, 10, 2);
        assertEquals(5, result, "10/2 = 5 (no exception)");
    }

    @Test
    void safeDivideByZero() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("safeDivide", int.class, int.class)
            .invoke(instance, 10, 0);
        assertEquals(-1, result, "10/0 should return -1 (caught)");
    }

    @Test
    void divideWithDefaultNormal() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("divideWithDefault", int.class, int.class)
            .invoke(instance, 20, 4);
        assertEquals(5, result);
    }

    @Test
    void divideWithDefaultByZero() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("divideWithDefault", int.class, int.class)
            .invoke(instance, 20, 0);
        assertEquals(0, result);
    }

    @Test
    void testFinallyNormal() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("testFinally", int.class)
            .invoke(instance, 2);
        assertEquals(50, result); // 100/2 = 50
    }

    @Test
    void testFinallyByZero() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("testFinally", int.class)
            .invoke(instance, 0);
        assertEquals(-1, result); // caught division by zero
    }

    private Object processAndLoad() throws Exception {
        String classPath = "opaddon/e2e/samples/ExceptionSample.class";
        Path classFile = Path.of("target", "test-classes", classPath);
        byte[] originalBytes = Files.readAllBytes(classFile);
        byte[] processedBytes = ClassRewriter.processClass(originalBytes, opts);

        assertTrue(processedBytes.length > 0);
        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.ExceptionSample", processedBytes);
        Class<?> processedClass = loader.loadClass("opaddon.e2e.samples.ExceptionSample");
        return processedClass.getDeclaredConstructor().newInstance();
    }
}
