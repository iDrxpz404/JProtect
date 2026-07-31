package opaddon.e2e.samples;

import opaddon.annotation.Virtualize;
import java.util.Arrays;

/**
 * Mix of invokedynamic and protectable methods in one class.
 */
public class IndySample {

    /** Uses string concat (invokedynamic in Java 9+) — should be skipped */
    @Virtualize
    public String greet(String name) {
        return "Hello, " + name + "!";
    }

    /** Uses lambda (invokedynamic) — should be skipped */
    @Virtualize
    public int sumWithLambda(int[] arr) {
        return Arrays.stream(arr).sum();
    }

    /** Pure arithmetic — should be virtualized normally */
    @Virtualize
    public int multiply(int a, int b) {
        return a * b;
    }
}
