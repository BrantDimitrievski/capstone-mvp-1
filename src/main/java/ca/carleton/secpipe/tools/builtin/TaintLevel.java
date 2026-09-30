package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;

/** How strongly an expression is believed to carry attacker-controlled data. */
public enum TaintLevel {
    /** Constant or derived only from trusted values. */
    NONE,
    /** Comes from a method parameter; callers may pass untrusted data. */
    PARAMETER,
    /** Comes directly from HTTP request input (getParameter, @RequestParam, ...). */
    REQUEST;

    public static TaintLevel max(TaintLevel a, TaintLevel b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    public Confidence confidence() {
        return switch (this) {
            case REQUEST -> Confidence.HIGH;
            case PARAMETER -> Confidence.MEDIUM;
            case NONE -> Confidence.LOW;
        };
    }
}
