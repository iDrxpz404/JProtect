package opaddon.e2e.samples;

import opaddon.annotation.Virtualize;

/**
 * Test fixture with exception handling for validating try/catch support.
 */
public class ExceptionSample {

    /** Simple catch: division by zero returns -1 */
    @Virtualize
    public int safeDivide(int a, int b) {
        try {
            return a / b;
        } catch (ArithmeticException e) {
            return -1;
        }
    }

    /** Catch with finally-like pattern */
    @Virtualize
    public int divideWithDefault(int a, int b) {
        try {
            return a / b;
        } catch (ArithmeticException e) {
            return 0;
        }
    }

    /** Multiple catch-like behavior with if/else (since Java doesn't have multi-catch in simple form) */
    @Virtualize
    public String parseOrNull(String s) {
        try {
            return s.toUpperCase();
        } catch (NullPointerException e) {
            return null;
        }
    }

    /** Finally block: ensure cleanup runs */
    @Virtualize
    public int testFinally(int n) {
        int x = 0;
        try {
            x = 100 / n;
            return x;
        } catch (ArithmeticException e) {
            return -1;
        }
    }
}
