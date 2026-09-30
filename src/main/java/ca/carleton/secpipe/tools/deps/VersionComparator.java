package ca.carleton.secpipe.tools.deps;

import java.util.Comparator;
import java.util.Locale;

/** Good-enough Maven-style version ordering (1.2.10 > 1.2.9, 2.0 > 2.0-rc1). */
public final class VersionComparator implements Comparator<String> {

    public static final VersionComparator INSTANCE = new VersionComparator();

    @Override
    public int compare(String a, String b) {
        String[] pa = a.toLowerCase(Locale.ROOT).split("[.\\-_+]");
        String[] pb = b.toLowerCase(Locale.ROOT).split("[.\\-_+]");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            String x = i < pa.length ? pa[i] : "";
            String y = i < pb.length ? pb[i] : "";
            int c = comparePart(x, y);
            if (c != 0) return c;
        }
        return 0;
    }

    private static int comparePart(String x, String y) {
        boolean nx = x.chars().allMatch(Character::isDigit) && !x.isEmpty();
        boolean ny = y.chars().allMatch(Character::isDigit) && !y.isEmpty();
        if (nx && ny) {
            return new java.math.BigInteger(x).compareTo(new java.math.BigInteger(y));
        }
        if (x.equals(y)) return 0;
        // A missing part or a release qualifier sorts after pre-release qualifiers (alpha, beta, rc, snapshot).
        int rx = rank(x);
        int ry = rank(y);
        if (rx != ry) return Integer.compare(rx, ry);
        if (nx) return 1;
        if (ny) return -1;
        return x.compareTo(y);
    }

    private static int rank(String q) {
        if (q.isEmpty() || q.equals("final") || q.equals("ga") || q.equals("release")) return 3;
        if (q.chars().allMatch(Character::isDigit)) return 4;
        if (q.startsWith("snapshot")) return 0;
        if (q.startsWith("alpha") || q.equals("a")) return 1;
        if (q.startsWith("beta") || q.equals("b") || q.startsWith("m") || q.startsWith("rc") || q.startsWith("cr")) return 2;
        return 3;
    }
}
