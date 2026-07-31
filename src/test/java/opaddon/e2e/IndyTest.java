package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that classes with a mix of invokedynamic and protectable methods
 * are handled correctly: indy methods are skipped, others are virtualized.
 */
class IndyTest {

    @Test
    void mixedIndyAndNormalMethods() throws Exception {
        CliOptions opts = CliOptions.parse(new String[]{
            "--input", "dummy.jar", "--output", "dummy-out.jar", "--seed", "42"});
        Path classFile = Path.of("target", "test-classes",
            "opaddon/e2e/samples/IndySample.class");
        byte[] orig = Files.readAllBytes(classFile);
        byte[] processed = ClassRewriter.processClass(orig, opts);

        Loader ldr = new Loader("opaddon.e2e.samples.IndySample", processed);
        Class<?> c = ldr.loadClass("opaddon.e2e.samples.IndySample");
        Object inst = c.getDeclaredConstructor().newInstance();

        // greet() uses string concat (indy) — should be skipped, still work
        Object greet = c.getMethod("greet", String.class).invoke(inst, "World");
        assertEquals("Hello, World!", greet, "String concat method should work (skipped)");

        // sumWithLambda uses lambda (indy) — should be skipped, still work
        Object sum = c.getMethod("sumWithLambda", int[].class).invoke(inst, new int[]{1,2,3});
        assertEquals(6, sum, "Lambda method should work (skipped)");

        // multiply is pure arithmetic — should be virtualized and work
        Object mul = c.getMethod("multiply", int.class, int.class).invoke(inst, 6, 7);
        assertEquals(42, mul, "Pure method should be virtualized");
    }

    static class Loader extends ClassLoader {
        final String name; final byte[] bytes;
        Loader(String n, byte[] b) { name=n; bytes=b; }
        @Override protected Class<?> findClass(String n) throws ClassNotFoundException {
            if (n.equals(name)) return defineClass(n, bytes, 0, bytes.length);
            return super.findClass(n);
        }
    }
}
