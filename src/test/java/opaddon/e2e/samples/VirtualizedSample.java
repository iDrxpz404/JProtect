package opaddon.e2e.samples;

import opaddon.annotation.Virtualize;

/**
 * Test fixture with @Virtualize-annotated methods for end-to-end testing.
 */
public class VirtualizedSample {

    @Virtualize
    public int addVirtualized(int a, int b) {
        return a + b;
    }

    @Virtualize
    public int multiplyVirtualized(int a, int b) {
        return a * b;
    }

    @Virtualize
    public int maxVirtualized(int a, int b) {
        return a > b ? a : b;
    }

    @Virtualize
    public int sumToNVirtualized(int n) {
        int s = 0;
        for (int i = 1; i <= n; i++) {
            s += i;
        }
        return s;
    }

    @Virtualize
    public int factorialVirtualized(int n) {
        int r = 1;
        for (int i = 2; i <= n; i++) {
            r *= i;
        }
        return r;
    }

    @Virtualize
    public int signVirtualized(int x) {
        if (x > 0) return 1;
        else if (x < 0) return -1;
        else return 0;
    }

    @Virtualize
    public String gradeVirtualized(int score) {
        if (score >= 90) return "A";
        else if (score >= 80) return "B";
        else if (score >= 70) return "C";
        else return "F";
    }

    @Virtualize
    public long longAddVirtualized(long a, long b) {
        return a + b;
    }

    @Virtualize
    public double doubleMulVirtualized(double a, double b) {
        return a * b;
    }

    // Non-virtualized method for comparison
    public int add(int a, int b) {
        return a + b;
    }
}
