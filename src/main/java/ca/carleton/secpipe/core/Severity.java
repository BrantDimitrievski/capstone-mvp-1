package ca.carleton.secpipe.core;

import java.util.Locale;

public enum Severity {
    CRITICAL(10.0),
    HIGH(7.5),
    MEDIUM(5.0),
    LOW(2.5),
    INFO(1.0);

    private final double weight;

    Severity(double weight) {
        this.weight = weight;
    }

    public double weight() {
        return weight;
    }

    public boolean atLeast(Severity other) {
        return this.ordinal() <= other.ordinal();
    }

    public static Severity max(Severity a, Severity b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.ordinal() <= b.ordinal() ? a : b;
    }

    /** Parses tool-specific severity labels (GHSA "MODERATE", Semgrep "ERROR", CVSS scores, ...). */
    public static Severity parse(String raw) {
        if (raw == null || raw.isBlank()) return MEDIUM;
        String s = raw.trim().toUpperCase(Locale.ROOT);
        switch (s) {
            case "CRITICAL":
                return CRITICAL;
            case "HIGH":
            case "ERROR":
                return HIGH;
            case "MEDIUM":
            case "MODERATE":
            case "WARNING":
                return MEDIUM;
            case "LOW":
            case "NOTE":
                return LOW;
            case "INFO":
            case "INFORMATIONAL":
            case "NEGLIGIBLE":
            case "NONE":
                return INFO;
            default:
                break;
        }
        try {
            return fromCvss(Double.parseDouble(s));
        } catch (NumberFormatException e) {
            return MEDIUM;
        }
    }

    public static Severity fromCvss(double score) {
        if (score >= 9.0) return CRITICAL;
        if (score >= 7.0) return HIGH;
        if (score >= 4.0) return MEDIUM;
        if (score > 0.0) return LOW;
        return INFO;
    }
}
