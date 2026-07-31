package opaddon.e2e.samples;

/**
 * Test fixture with loop-based methods.
 */
public class LoopSample {

    /** Simple counted loop */
    public int sumToN(int n) {
        int s = 0;
        for (int i = 1; i <= n; i++) {
            s += i;
        }
        return s;
    }

    /** Factorial */
    public int factorial(int n) {
        int r = 1;
        for (int i = 2; i <= n; i++) {
            r *= i;
        }
        return r;
    }

    /** While loop */
    public int gcd(int a, int b) {
        while (b != 0) {
            int t = b;
            b = a % b;
            a = t;
        }
        return a;
    }
}
