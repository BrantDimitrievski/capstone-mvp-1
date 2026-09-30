package ca.carleton.secpipe.core;

public enum Confidence {
    HIGH(1.0),
    MEDIUM(0.75),
    LOW(0.5);

    private final double factor;

    Confidence(double factor) {
        this.factor = factor;
    }

    public double factor() {
        return factor;
    }

    public static Confidence max(Confidence a, Confidence b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.ordinal() <= b.ordinal() ? a : b;
    }

    public Confidence raise() {
        return this == LOW ? MEDIUM : HIGH;
    }
}
