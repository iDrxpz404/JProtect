package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.Test;
import java.nio.file.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Performance benchmarks comparing virtualized vs. original execution.
 */
class BenchmarkTest {

    private static final int WARMUP = 5000;
    private static final int ITERATIONS = 50000;

    @Test
    void benchmarkFactorial() throws Exception {
        CliOptions opts = CliOptions.parse(new String[]{
            "--input", "dummy.jar", "--output", "dummy-out.jar", "--seed", "42"});

        Path classFile = Path.of("target", "test-classes",
            "opaddon/e2e/samples/VirtualizedSample.class");
        byte[] processed = ClassRewriter.processClass(Files.readAllBytes(classFile), opts);

        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.VirtualizedSample", processed);
        Class<?> clazz = loader.loadClass("opaddon.e2e.samples.VirtualizedSample");
        Object vInstance = clazz.getDeclaredConstructor().newInstance();
        Object oInstance = clazz.getDeclaredConstructor().newInstance();

        // Load original class for baseline comparison
        Class<?> origClass = Class.forName("opaddon.e2e.samples.VirtualizedSample");
        Object origInstance = origClass.getDeclaredConstructor().newInstance();

        // Use addVirtualized for both — same method signature and logic
        // Virtualized: runs through VM interpreter
        // Original: runs as direct JVM bytecode
        java.lang.reflect.Method virtMethod = clazz.getMethod("addVirtualized", int.class, int.class);
        java.lang.reflect.Method origMethod = origClass.getMethod("addVirtualized", int.class, int.class);

        // Warmup
        for (int i = 0; i < WARMUP; i++) {
            virtMethod.invoke(vInstance, i, i + 1);
            origMethod.invoke(origInstance, i, i + 1);
        }

        // Benchmark virtualized
        long vStart = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            virtMethod.invoke(vInstance, 3, 5);
        }
        long vTime = System.nanoTime() - vStart;

        // Benchmark original
        long oStart = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            origMethod.invoke(origInstance, 3, 5);
        }
        long oTime = System.nanoTime() - oStart;

        double vNs = (double) vTime / ITERATIONS;
        double oNs = (double) oTime / ITERATIONS;
        double ratio = vNs / oNs;

        System.out.printf("%n=== Benchmark: addVirtualized(3,5) ===%n");
        System.out.printf("Virtualized (VM interpreter): %.0f ns/call%n", vNs);
        System.out.printf("Original   (JVM bytecode):    %.0f ns/call%n", oNs);
        System.out.printf("Slowdown:                     %.1fx%n", ratio);
        System.out.printf("(Warmup: %d, Measured: %d iterations)%n", WARMUP, ITERATIONS);

        // Virtualized should be slower but less than 100x
        assertTrue(ratio < 100, "Virtualized should be less than 100x slower, was " + ratio + "x");
    }

    private static final class ByteClassLoader extends ClassLoader {
        private final String className; private final byte[] bytes;
        ByteClassLoader(String c, byte[] b) { this.className = c; this.bytes = b; }
        @Override protected Class<?> findClass(String n) throws ClassNotFoundException {
            if (n.equals(className)) return defineClass(n, bytes, 0, bytes.length);
            return super.findClass(n);
        }
    }
}
