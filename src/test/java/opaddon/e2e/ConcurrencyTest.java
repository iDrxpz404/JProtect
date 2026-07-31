package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that multiple threads can execute virtualized methods concurrently
 * without corrupting VM state.
 */
class ConcurrencyTest {

    private static final class ByteClassLoader extends ClassLoader {
        private final String className;
        private final byte[] bytes;
        ByteClassLoader(String c, byte[] b) { this.className = c; this.bytes = b; }
        @Override protected Class<?> findClass(String n) throws ClassNotFoundException {
            if (n.equals(className)) return defineClass(n, bytes, 0, bytes.length);
            return super.findClass(n);
        }
    }

    @Test
    void concurrentMethodCallsDoNotCorruptState() throws Exception {
        CliOptions opts = CliOptions.parse(new String[]{
            "--input", "dummy.jar", "--output", "dummy-out.jar", "--seed", "42"});

        Path classFile = Path.of("target", "test-classes",
            "opaddon/e2e/samples/VirtualizedSample.class");
        byte[] original = Files.readAllBytes(classFile);
        byte[] processed = ClassRewriter.processClass(original, opts);

        ByteClassLoader loader = new ByteClassLoader(
            "opaddon.e2e.samples.VirtualizedSample", processed);
        Class<?> clazz = loader.loadClass("opaddon.e2e.samples.VirtualizedSample");

        int threads = 8;
        int iterations = 100;
        ExecutorService exec = Executors.newFixedThreadPool(threads);
        AtomicInteger errors = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(threads);

        for (int t = 0; t < threads; t++) {
            final int threadId = t;
            exec.submit(() -> {
                try {
                    Object instance = clazz.getDeclaredConstructor().newInstance();
                    for (int i = 0; i < iterations; i++) {
                        int a = threadId * 1000 + i;
                        int b = i + 1;
                        Object result = clazz
                            .getMethod("addVirtualized", int.class, int.class)
                            .invoke(instance, a, b);
                        if (!(result instanceof Integer) ||
                            ((Integer) result) != a + b) {
                            errors.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                    e.printStackTrace();
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(30, TimeUnit.SECONDS);
        exec.shutdown();

        assertEquals(0, errors.get(),
            "Concurrent execution should produce zero errors across " +
            threads + " threads × " + iterations + " iterations");
    }
}
