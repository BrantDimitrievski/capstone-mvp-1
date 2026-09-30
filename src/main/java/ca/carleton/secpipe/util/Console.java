package ca.carleton.secpipe.util;

import ca.carleton.secpipe.core.Severity;

import java.io.PrintStream;

/** Terminal output. Progress goes to stderr so stdout stays clean for summaries and piping. */
public class Console {

    private final PrintStream out;
    private final PrintStream err;
    private final boolean color;
    private final boolean quiet;
    private final boolean verbose;

    public Console(PrintStream out, PrintStream err, boolean color, boolean quiet, boolean verbose) {
        this.out = out;
        this.err = err;
        this.color = color;
        this.quiet = quiet;
        this.verbose = verbose;
    }

    public static Console system(boolean quiet, boolean verbose) {
        boolean color = System.console() != null
                && System.getenv("NO_COLOR") == null
                && !"dumb".equals(System.getenv("TERM"));
        return new Console(System.out, System.err, color, quiet, verbose);
    }

    public static Console silent() {
        PrintStream sink = new PrintStream(PrintStream.nullOutputStream());
        return new Console(sink, sink, false, true, false);
    }

    public void step(String message) {
        if (!quiet) err.println(paint("36", "==> ") + message);
    }

    public void info(String message) {
        if (!quiet) err.println("    " + message);
    }

    public void warn(String message) {
        err.println(paint("33", "warn: ") + message);
    }

    public void error(String message) {
        err.println(paint("31;1", "error: ") + message);
    }

    public void hint(String message) {
        err.println(paint("36", "hint:  ") + message);
    }

    public void debug(String message) {
        if (verbose) err.println(paint("2", "    [debug] " + message));
    }

    public void println(String line) {
        out.println(line);
    }

    public void println() {
        out.println();
    }

    public boolean isVerbose() {
        return verbose;
    }

    public String bold(String s) {
        return paint("1", s);
    }

    public String dim(String s) {
        return paint("2", s);
    }

    public String green(String s) {
        return paint("32", s);
    }

    public String yellow(String s) {
        return paint("33", s);
    }

    public String red(String s) {
        return paint("31", s);
    }

    public String severity(Severity severity) {
        String label = String.format("%-8s", severity.name());
        return switch (severity) {
            case CRITICAL -> paint("97;41;1", label);
            case HIGH -> paint("31;1", label);
            case MEDIUM -> paint("33", label);
            case LOW -> paint("36", label);
            case INFO -> paint("2", label);
        };
    }

    private String paint(String code, String s) {
        return color ? "\u001b[" + code + "m" + s + "\u001b[0m" : s;
    }
}
