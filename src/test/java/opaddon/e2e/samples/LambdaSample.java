package opaddon.e2e.samples;

import opaddon.annotation.Virtualize;

/**
 * Test fixture with invokedynamic (lambdas, string concat).
 * These methods should be gracefully skipped by the virtualizer.
 */
public class LambdaSample {

    /** Uses a lambda — contains invokedynamic for the lambda metafactory */
    @Virtualize
    public int lambdaSum(int[] arr) {
        // This creates a lambda: invokedynamic will appear in the bytecode
        return java.util.Arrays.stream(arr).sum();
    }

    /** String concatenation uses invokedynamic in Java 9+ */
    @Virtualize
    public String modernConcat(String a, String b) {
        return a + b;
    }

    /** Non-lambda method for comparison — should still be virtualized */
    @Virtualize
    public int plainAdd(int a, int b) {
        return a + b;
    }
}
