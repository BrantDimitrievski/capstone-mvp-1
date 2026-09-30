package ca.carleton.secpipe.tools.deps;

import java.util.HashMap;
import java.util.Map;
import java.util.OptionalDouble;

/** CVSS v3.x base score from a vector string such as {@code CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H}. */
public final class Cvss3 {

    private Cvss3() {
    }

    public static OptionalDouble baseScore(String vector) {
        if (vector == null || !vector.startsWith("CVSS:3")) return OptionalDouble.empty();
        Map<String, String> m = new HashMap<>();
        for (String part : vector.split("/")) {
            String[] kv = part.split(":");
            if (kv.length == 2) m.put(kv[0], kv[1]);
        }
        try {
            boolean changed = "C".equals(m.get("S"));
            double av = switch (m.get("AV")) { case "N" -> 0.85; case "A" -> 0.62; case "L" -> 0.55; default -> 0.2; };
            double ac = "L".equals(m.get("AC")) ? 0.77 : 0.44;
            double pr = switch (m.get("PR")) {
                case "N" -> 0.85;
                case "L" -> changed ? 0.68 : 0.62;
                default -> changed ? 0.5 : 0.27;
            };
            double ui = "N".equals(m.get("UI")) ? 0.85 : 0.62;
            double c = cia(m.get("C"));
            double i = cia(m.get("I"));
            double a = cia(m.get("A"));
            double iss = 1 - (1 - c) * (1 - i) * (1 - a);
            double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
            double exploitability = 8.22 * av * ac * pr * ui;
            if (impact <= 0) return OptionalDouble.of(0.0);
            double score = changed ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
            return OptionalDouble.of(roundUp(score));
        } catch (RuntimeException e) {
            return OptionalDouble.empty();
        }
    }

    private static double cia(String v) {
        return switch (v) { case "H" -> 0.56; case "L" -> 0.22; default -> 0.0; };
    }

    private static double roundUp(double d) {
        long i = Math.round(d * 100000);
        if (i % 10000 == 0) return i / 100000.0;
        return (Math.floor(i / 10000.0) + 1) / 10.0;
    }
}
