package opaddon.e2e.samples;

/**
 * Simple test fixture for Phase 1 round-trip verification.
 * This class will be compiled normally by Maven, then its .class file
 * will be round-tripped through ClassRewriter to verify the pipeline.
 */
public class ArithmeticSample {

    public int add(int a, int b) {
        return a + b;
    }

    public int multiply(int a, int b) {
        return a * b;
    }

    public int complex(int x, int y, int z) {
        return x * y + z;
    }

    public long longAdd(long a, long b) {
        return a + b;
    }

    public double doubleMul(double a, double b) {
        return a * b;
    }

    public String concat(String a, String b) {
        return a + b;
    }

    public boolean isPositive(int x) {
        return x > 0;
    }

    public int conditional(int x) {
        return x > 0 ? 1 : -1;
    }
}
