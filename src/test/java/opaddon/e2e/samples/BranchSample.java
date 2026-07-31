package opaddon.e2e.samples;

/**
 * Test fixture with branch-heavy methods.
 */
public class BranchSample {

    /** Simple if/else */
    public int max(int a, int b) {
        return a > b ? a : b;
    }

    /** Nested branches */
    public int sign(int x) {
        if (x > 0) return 1;
        else if (x < 0) return -1;
        else return 0;
    }

    /** Chain of if/else-if */
    public String grade(int score) {
        if (score >= 90) return "A";
        else if (score >= 80) return "B";
        else if (score >= 70) return "C";
        else return "F";
    }

    /** AND / OR short-circuit (compiles to branches) */
    public boolean inRange(int x, int lo, int hi) {
        return x >= lo && x <= hi;
    }
}
