import opaddon.annotation.Virtualize;

/**
 * Protected License Manager — secret algorithms hidden from decompilers.
 *
 * BUILD & RUN:
 *   cd demo && javac --release 17 -cp src -d original src/opaddon/annotation/Virtualize.java src/LicenseManager.java
 *   cd original && jar cf ../original.jar . && cd ../..
 *   java -jar target/virtualizer.jar --input demo/original.jar --output demo/protected.jar --config demo/aggressive.json
 *   java -cp target/classes:demo/protected LicenseManager
 */
public class LicenseManager {

    private static final String LICENSE_KEY = "XK7m-9pQ2-vR4n-W8sT";

    public static void main(String[] args) {
        LicenseManager lm = new LicenseManager();
        String key = args.length > 0 ? args[0] : "bad-key";
        System.out.println("License:  " + lm.validateLicense(key));
        System.out.println("Score:    " + lm.computeRiskScore(85, 3, 12000));
        System.out.println("Factorial:" + lm.factorial(10));
        System.out.println("Gcd:      " + lm.gcd(48, 18));
        System.out.println("Sign:     " + lm.sign(-42));
        System.out.println("Sum:      " + lm.sumToN(100));
        System.out.println("Version:  " + lm.getVersion());
    }

    @Virtualize
    public boolean validateLicense(String key) {
        if (key == null || key.length() < 8) return false;
        int sum = 0, xor = 0;
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            sum += (c * (i + 1)) & 0xFF;
            xor ^= c;
        }
        if (sum != 0xAD || xor != 0x2F) return false;
        String[] parts = key.split("-");
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (p.length() != 4) return false;
        }
        return key.equals(LICENSE_KEY);
    }

    @Virtualize
    public int computeRiskScore(int base, int sev, int amount) {
        int score = base;
        if (sev > 0) score += (sev * sev) / 10;
        if (amount > 0) {
            int log = 0, t = amount;
            while (t > 1) { t >>= 1; log++; }
            score += log * 5;
        }
        if (score > 1000) score = 1000;
        if (score < 0) score = 0;
        return score;
    }

    @Virtualize
    public int factorial(int n) {
        if (n <= 1) return 1;
        int r = 1;
        for (int i = 2; i <= n; i++) r *= i;
        return r;
    }

    @Virtualize
    public int gcd(int a, int b) {
        while (b != 0) { int t = b; b = a % b; a = t; }
        return a;
    }

    @Virtualize
    public int sign(int x) {
        if (x > 0) return 1;
        if (x < 0) return -1;
        return 0;
    }

    @Virtualize
    public int sumToN(int n) {
        int s = 0;
        for (int i = 1; i <= n; i++) s += i;
        return s;
    }

    public String getVersion() { return "LicenseManager v4.2"; }
}
