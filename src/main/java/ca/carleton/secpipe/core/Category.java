package ca.carleton.secpipe.core;

public enum Category {
    /** Findings in first-party source code (SAST). */
    CODE,
    /** Known vulnerabilities in third-party dependencies (SCA). */
    DEPENDENCIES
}
