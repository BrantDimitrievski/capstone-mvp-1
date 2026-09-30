package ca.carleton.secpipe.core;

/** A user-facing failure: the message says what went wrong and the hint says how to fix it. */
public class SecPipeException extends Exception {

    private final String hint;

    public SecPipeException(String message, String hint) {
        super(message);
        this.hint = hint;
    }

    public SecPipeException(String message, String hint, Throwable cause) {
        super(message, cause);
        this.hint = hint;
    }

    public String hint() {
        return hint;
    }
}
