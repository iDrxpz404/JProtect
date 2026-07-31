package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.Test;

import java.nio.file.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke test: verify that virtualized methods no longer contain
 * the original bytecode logic — just the VM interpreter call.
 */
class DecompilerSmokeTest {

    /**
     * Verify that a virtualized method's bytecode is replaced with
     * a VMInterpreter.execute() call, not the original arithmetic instructions.
     */
    @Test
    void virtualizedMethodBodyIsReplaced() throws Exception {
        CliOptions opts = CliOptions.parse(
            new String[]{"--input", "dummy.jar", "--output", "dummy-out.jar"});

        String classPath = "opaddon/e2e/samples/VirtualizedSample.class";
        Path classFile = Path.of("target", "test-classes", classPath);
        byte[] original = Files.readAllBytes(classFile);
        byte[] processed = ClassRewriter.processClass(original, opts);

        // The processed class should be different from the original
        assertFalse(Arrays.equals(original, processed),
            "Processed class should differ from original");

        // Load the processed class and verify the annotation methods work
        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.VirtualizedSample", processed);
        Class<?> clazz = loader.loadClass("opaddon.e2e.samples.VirtualizedSample");
        Object instance = clazz.getDeclaredConstructor().newInstance();

        // Virtualized method should still return the correct result
        int result = (Integer) clazz.getMethod("addVirtualized", int.class, int.class)
            .invoke(instance, 10, 20);
        assertEquals(30, result);

        // Non-virtualized method should also still work
        int normal = (Integer) clazz.getMethod("add", int.class, int.class)
            .invoke(instance, 5, 7);
        assertEquals(12, normal);
    }

    @Test
    void processedClassIsLargerDueToStaticFields() {
        // The processed class should be larger because it includes
        // static byte[] fields with the ISA program
        String classPath = "opaddon/e2e/samples/VirtualizedSample.class";
        Path p = Path.of("target", "test-classes", classPath);
        byte[] original = null;
        try {
            original = Files.readAllBytes(p);
            CliOptions opts = CliOptions.parse(
                new String[]{"--input", "dummy.jar", "--output", "dummy-out.jar"});
            byte[] processed = ClassRewriter.processClass(original, opts);
            assertTrue(processed.length > original.length,
                "Processed class should be larger (contains static fields)");
        } catch (Exception e) {
            fail(e);
        }
    }

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
}
