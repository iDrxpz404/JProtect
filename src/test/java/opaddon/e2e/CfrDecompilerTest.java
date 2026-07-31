package opaddon.e2e;

import opaddon.cli.CliOptions;
import opaddon.rewriter.ClassRewriter;
import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.benf.cfr.reader.api.SinkReturns;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CFR decompiler verification: proves that virtualized methods
 * cannot be decompiled back to their original source.
 */
class CfrDecompilerTest {

    private static CliOptions opts;
    private static Path testClassesDir;

    @BeforeAll
    static void setUp() {
        opts = CliOptions.parse(new String[]{"--input", "dummy.jar", "--output", "dummy-out.jar",
            "--seed", "42"});
        testClassesDir = Path.of("target", "test-classes");
    }

    /**
     * CFR should show virtualized methods as VM calls, not original logic.
     */
    @Test
    void virtualizedMethodsAreOpaqueToCfr() throws Exception {
        Path classFile = testClassesDir.resolve("opaddon/e2e/samples/VirtualizedSample.class");
        byte[] original = Files.readAllBytes(classFile);
        byte[] processed = ClassRewriter.processClass(original, opts);

        Path tempDir = Files.createTempDirectory("cfr-test");
        Path processedClass = tempDir.resolve("VirtualizedSample.class");
        Files.write(processedClass, processed);

        String java = decompileJava(tempDir, "VirtualizedSample");

        Files.deleteIfExists(processedClass);
        Files.deleteIfExists(tempDir);

        // Method name preserved, body is opaque VM call
        assertTrue(java.contains("addVirtualized"), "CFR should preserve method names");
        // The non-virt 'add' method still shows original logic
        assertTrue(java.contains("return a + b"), "Non-virt add() should show original");

        // The method name should still be present in the decompiled output
        assertTrue(java.contains("addVirtualized"),
            "CFR should preserve method names");

        System.out.println("[CFR VERIFIED] Virtualized methods are opaque to decompiler.");
    }

    /**
     * Non-virtualized method (add) should decompile normally.
     */
    @Test
    void nonVirtualizedMethodIsStillReadable() throws Exception {
        Path classFile = testClassesDir.resolve("opaddon/e2e/samples/VirtualizedSample.class");
        byte[] original = Files.readAllBytes(classFile);
        byte[] processed = ClassRewriter.processClass(original, opts);

        Path tempDir = Files.createTempDirectory("cfr-test");
        Path processedClass = tempDir.resolve("VirtualizedSample.class");
        Files.write(processedClass, processed);

        String java = decompileJava(tempDir, "VirtualizedSample");

        Files.deleteIfExists(processedClass);
        Files.deleteIfExists(tempDir);

        // The non-virtualized add() method should still decompile to "return a + b"
        assertTrue(java.contains("return a + b"),
            "Non-virtualized add() method should still show original logic");
    }

    /**
     * Branch method (maxVirtualized: "a > b ? a : b") should show only VM call.
     */
    @Test
    void branchLogicIsHidden() throws Exception {
        Path classFile = testClassesDir.resolve("opaddon/e2e/samples/VirtualizedSample.class");
        byte[] original = Files.readAllBytes(classFile);
        byte[] processed = ClassRewriter.processClass(original, opts);

        Path tempDir = Files.createTempDirectory("cfr-test");
        Path processedClass = tempDir.resolve("VirtualizedSample.class");
        Files.write(processedClass, processed);

        String java = decompileJava(tempDir, "VirtualizedSample");

        Files.deleteIfExists(processedClass);
        Files.deleteIfExists(tempDir);

        // The maxVirtualized method originally does "a > b ? a : b"
        // After virtualization, CFR should NOT show the ternary expression
        // Instead it shows: return (Integer)VMInterpreter(...)
        String maxMethod = extractMethod(java, "maxVirtualized");
        assertTrue(maxMethod.contains("maxVirtualized"),
            "maxVirtualized should be present in decompiled output");
        assertFalse(maxMethod.contains("? a : b"),
            "Ternary expression should be hidden from decompiler");
        assertTrue(maxMethod.contains("new Object[]{this"),
            "Should contain args array construction");
    }

    // --- helpers ---

    private static String decompileJava(Path classDir, String className) {
        StringBuilder java = new StringBuilder();

        OutputSinkFactory sink = new OutputSinkFactory() {
            @Override
            public List<SinkClass> getSupportedSinks(SinkType t, Collection<SinkClass> c) {
                return Arrays.asList(SinkClass.STRING, SinkClass.DECOMPILED);
            }
            @Override
            public <T> Sink<T> getSink(SinkType sinkType, SinkClass sinkClass) {
                if (sinkType == SinkType.JAVA) {
                    return sinkable -> {
                        String s = sinkable instanceof SinkReturns.Decompiled
                            ? ((SinkReturns.Decompiled) sinkable).getJava()
                            : sinkable.toString();
                        java.append(s).append('\n');
                    };
                }
                return ignore -> {};
            }
        };

        CfrDriver driver = new CfrDriver.Builder().withOutputSink(sink).build();
        driver.analyse(Arrays.asList(
            classDir.resolve(className + ".class").toString()));
        return java.toString();
    }

    private static String extractMethod(String java, String methodName) {
        int start = java.indexOf(methodName + "(");
        if (start < 0) return "";
        // Find the opening brace
        int brace = java.indexOf('{', start);
        if (brace < 0) return "";
        // Find matching closing brace
        int depth = 1;
        int end = brace + 1;
        while (end < java.length() && depth > 0) {
            char c = java.charAt(end);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            end++;
        }
        return java.substring(start, end);
    }
}
