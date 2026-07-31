package opaddon.rewriter;

import opaddon.cli.CliOptions;
import opaddon.e2e.samples.ArithmeticSample;
import org.junit.jupiter.api.Test;

import java.nio.file.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 1: Validates that ClassRewriter can read and write a class
 * without changing its behavior.
 */
class ClassRewriterTest {

    /**
     * Custom ClassLoader that loads a .class file from a byte array.
     */
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

    /**
     * Round-trips the ArithmeticSample class through ClassRewriter and
     * verifies the processed class behaves identically to the original.
     */
    @Test
    void roundTripArithmeticSample() throws Exception {
        // Read the compiled .class file from the test output directory
        String classPath = "opaddon/e2e/samples/ArithmeticSample.class";
        Path classFile = findClassFile(classPath);
        byte[] originalBytes = Files.readAllBytes(classFile);

        // Show that we're actually processing something meaningful
        assertTrue(originalBytes.length > 100, "Class file should be non-trivial");

        // Process through ClassRewriter (Phase 1: pass-through)
        byte[] processedBytes = ClassRewriter.processClass(originalBytes, quietOpts());

        // The processed class should be valid bytecode
        assertTrue(processedBytes.length > 100, "Processed class should be non-trivial");

        // Load the processed class and verify it works
        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.ArithmeticSample", processedBytes);
        Class<?> processedClass = loader.loadClass("opaddon.e2e.samples.ArithmeticSample");
        Object instance = processedClass.getDeclaredConstructor().newInstance();

        // Test all methods via reflection against the ORIGINAL instance
        ArithmeticSample original = new ArithmeticSample();

        assertEquals(original.add(3, 5), invoke(processedClass, instance, "add",
            new Class<?>[]{int.class, int.class}, 3, 5));
        assertEquals(original.multiply(4, 7), invoke(processedClass, instance, "multiply",
            new Class<?>[]{int.class, int.class}, 4, 7));
        assertEquals(original.complex(2, 3, 4), invoke(processedClass, instance, "complex",
            new Class<?>[]{int.class, int.class, int.class}, 2, 3, 4));
        assertEquals(original.longAdd(100L, 200L), invoke(processedClass, instance, "longAdd",
            new Class<?>[]{long.class, long.class}, 100L, 200L));
        assertEquals(original.doubleMul(2.5, 3.0), (Double) invoke(processedClass, instance, "doubleMul",
            new Class<?>[]{double.class, double.class}, 2.5, 3.0), 0.0001);
        assertEquals(original.concat("hello", "world"),
            invoke(processedClass, instance, "concat",
                new Class<?>[]{String.class, String.class}, "hello", "world"));
        assertEquals(original.isPositive(5), invoke(processedClass, instance, "isPositive",
            new Class<?>[]{int.class}, 5));
        assertEquals(original.isPositive(-3), invoke(processedClass, instance, "isPositive",
            new Class<?>[]{int.class}, -3));
        assertEquals(original.conditional(7), invoke(processedClass, instance, "conditional",
            new Class<?>[]{int.class}, 7));
        assertEquals(original.conditional(-2), invoke(processedClass, instance, "conditional",
            new Class<?>[]{int.class}, -2));
    }

    /**
     * Round-trip the Virtualize annotation itself — it should survive unchanged.
     */
    @Test
    void roundTripAnnotationClass() throws Exception {
        String classPath = "opaddon/annotation/Virtualize.class";
        Path classFile = findClassFile(classPath);
        byte[] originalBytes = Files.readAllBytes(classFile);
        byte[] processedBytes = ClassRewriter.processClass(originalBytes, quietOpts());

        assertTrue(processedBytes.length > 50, "Annotation class should be non-trivial");

        // Load it back and verify it's still an annotation with the right name
        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.annotation.Virtualize", processedBytes);
        Class<?> processedClass = loader.loadClass("opaddon.annotation.Virtualize");
        assertTrue(processedClass.isAnnotation(),
            "Virtualize should still be an annotation after round-trip");
        assertEquals("opaddon.annotation.Virtualize", processedClass.getName());
    }

    private static CliOptions quietOpts() {
        String[] args = {"--input", "dummy.jar", "--output", "dummy-out.jar"};
        return CliOptions.parse(args);
    }

    // --- helpers ---

    private static Object invoke(Class<?> clazz, Object instance, String methodName,
                                  Class<?>[] paramTypes, Object... args) throws Exception {
        return clazz.getMethod(methodName, paramTypes).invoke(instance, args);
    }

    private static Path findClassFile(String classFilePath) {
        // Look in target/test-classes first, then target/classes
        Path p = Path.of("target", "test-classes", classFilePath);
        if (Files.exists(p)) return p;
        p = Path.of("target", "classes", classFilePath);
        if (Files.exists(p)) return p;
        throw new RuntimeException("Cannot find class file: " + classFilePath);
    }
}
