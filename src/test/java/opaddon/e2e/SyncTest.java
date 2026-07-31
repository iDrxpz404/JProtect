package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that virtualized synchronized methods work correctly.
 */
class SyncTest {

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

    @Test
    void syncAdd() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("syncAdd", int.class, int.class).invoke(instance, 3, 7);
        assertEquals(10, result);
    }

    @Test
    void syncBlock() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("syncBlock", int.class).invoke(instance, 5);
        assertEquals(10, result);
    }

    @Test
    void syncCounter() throws Exception {
        Object instance = processAndLoad();
        int result = (Integer) instance.getClass()
            .getMethod("syncCounter").invoke(instance);
        assertEquals(42, result);
    }

    private Object processAndLoad() throws Exception {
        String classPath = "opaddon/e2e/samples/SyncSample.class";
        Path classFile = Path.of("target", "test-classes", classPath);
        byte[] originalBytes = Files.readAllBytes(classFile);
        byte[] processedBytes = ClassRewriter.processClass(originalBytes, opts);
        assertTrue(processedBytes.length > 0);
        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.SyncSample", processedBytes);
        return loader.loadClass("opaddon.e2e.samples.SyncSample")
            .getDeclaredConstructor().newInstance();
    }
}
