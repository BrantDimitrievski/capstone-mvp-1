package ca.carleton.secpipe.tools;

/** Raised by an adapter when its analyzer could not complete. The pipeline records it and continues. */
public class ScanException extends Exception {

    public ScanException(String message) {
        super(message);
    }

    public ScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
