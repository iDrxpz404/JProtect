package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that methods with invokedynamic are gracefully skipped
 * rather than breaking the virtualizer.
 */
class InvokeDynamicSkipTest {

    private static final class ByteClassLoader extends ClassLoader {
        private final String className;
        private final byte[] bytes;
        ByteClassLoader(String className, byte[] bytes) {
            this.className = className; this.bytes = bytes;
        }
        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if (name.equals(className)) return defineClass(name, bytes, 0, bytes.length);
            return super.findClass(name);
        }
    }

    private static CliOptions opts;

    @BeforeAll
    static void setUp() {
        opts = CliOptions.parse(new String[]{"--input", "dummy.jar", "--output", "dummy-out.jar"});
    }

    /**
     * The lambdaSum method uses invokedynamic (lambda metafactory).
     * It should be SKIPPED by the virtualizer, meaning it runs as normal
     * JVM bytecode — not through the interpreter.
     */
    @Test
    void lambdaMethodIsSkippedAndStillWorks() throws Exception {
        Object instance = processAndLoad();
        int[] arr = {1, 2, 3, 4, 5};
        int result = (Integer) instance.getClass()
            .getMethod("lambdaSum", int[].class).invoke(instance, (Object) arr);
        assertEquals(15, result, "Lambda method should work (was skipped)");
    }

    /**
     * String concat uses invokedynamic in Java 9+.
     * Should be skipped and still work normally.
     */
    @Test
    void concatMethodIsSkippedAndStillWorks() throws Exception {
        Object instance = processAndLoad();
        String result = (String) instance.getClass()
            .getMethod("modernConcat", String.class, String.class)
            .invoke(instance, "hello", "world");
        assertEquals("helloworld", result, "String concat should work (was skipped)");
    }

    /**
     * The plainAdd method does NOT use invokedynamic.
     * It SHOULD be virtualized and work through the interpreter.
     */
    @Test
    void plainMethodIsStillVirtualized() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("plainAdd", int.class, int.class).invoke(instance, 3, 5);
        assertEquals(8, result, "Plain method should be virtualized");
    }

    private Object processAndLoad() throws Exception {
        String classPath = "opaddon/e2e/samples/LambdaSample.class";
        Path classFile = Path.of("target", "test-classes", classPath);
        byte[] originalBytes = Files.readAllBytes(classFile);
        byte[] processedBytes = ClassRewriter.processClass(originalBytes, opts);
        assertTrue(processedBytes.length > 0);
        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.LambdaSample", processedBytes);
        return loader.loadClass("opaddon.e2e.samples.LambdaSample")
            .getDeclaredConstructor().newInstance();
    }
}
