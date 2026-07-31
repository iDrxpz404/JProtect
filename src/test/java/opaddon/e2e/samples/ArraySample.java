package opaddon.e2e.samples;

/**
 * Test fixture with array operations.
 */
public class ArraySample {

    public int sum(int[] arr) {
        int s = 0;
        for (int i = 0; i < arr.length; i++) {
            s += arr[i];
        }
        return s;
    }

    public int firstPositive(int[] arr) {
        for (int v : arr) {
            if (v > 0) return v;
        }
        return -1;
    }
}
