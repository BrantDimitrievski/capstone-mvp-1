package com.example.vulnlab;

/** Seeded: CWE-798 hard-coded cloud credential. The labels below are not secrets and must not be flagged. */
public final class AppConfig {

    public static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    public static final String PASSWORD_PARAM = "password";
    public static final String PASSWORD_FIELD_LABEL = "Enter your password";

    private AppConfig() {
    }
}
