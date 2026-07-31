package opaddon.e2e.samples;

/**
 * Test fixture with field access.
 */
public class FieldSample {

    public int counter = 0;
    private String name = "default";

    public int incrementAndGet() {
        counter++;
        return counter;
    }

    public void setName(String n) {
        this.name = n;
    }

    public String getName() {
        return name;
    }

    // Static field
    public static int staticCount = 0;

    public static int incStatic() {
        staticCount++;
        return staticCount;
    }
}
