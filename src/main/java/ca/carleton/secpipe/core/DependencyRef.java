package ca.carleton.secpipe.core;

/** A third-party package coordinate, e.g. {@code org.apache.logging.log4j:log4j-core:2.14.1}. */
public record DependencyRef(String group, String artifact, String version, String fixedVersion) {

    public String coordinates() {
        return (group == null || group.isBlank() ? "" : group + ":") + artifact + ":" + version;
    }

    public String packageName() {
        return (group == null || group.isBlank() ? "" : group + ":") + artifact;
    }

    public DependencyRef withFixedVersion(String fixed) {
        return new DependencyRef(group, artifact, version, fixed);
    }
}
