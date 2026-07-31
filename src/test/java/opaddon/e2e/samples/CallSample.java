package opaddon.e2e.samples;

/**
 * Test fixture with method call patterns.
 */
public class CallSample {

    /** Simple delegation */
    public int delegateAdd(int a, int b) {
        return add(a, b);
    }

    private int add(int a, int b) {
        return a + b;
    }

    /** Static method call */
    public int abs(int x) {
        return Math.abs(x);
    }

    /** Chained calls */
    public String greet(String name) {
        return "Hello, ".concat(name).concat("!");
    }
}
