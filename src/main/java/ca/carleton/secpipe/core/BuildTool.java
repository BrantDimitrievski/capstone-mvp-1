package ca.carleton.secpipe.core;

public enum BuildTool {
    MAVEN_WRAPPER("Maven (wrapper)"),
    MAVEN("Maven"),
    GRADLE_WRAPPER("Gradle (wrapper)"),
    GRADLE("Gradle"),
    NONE("none detected");

    private final String label;

    BuildTool(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public boolean isMaven() {
        return this == MAVEN || this == MAVEN_WRAPPER;
    }

    public boolean isGradle() {
        return this == GRADLE || this == GRADLE_WRAPPER;
    }
}
