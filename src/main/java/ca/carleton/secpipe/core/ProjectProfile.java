package ca.carleton.secpipe.core;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * What the orchestrator learned about the target project before planning the scan.
 *
 * @param root       absolute project root
 * @param language   detected (or requested) language, e.g. "java"
 * @param buildTool  build tool detected from wrapper scripts and manifests
 * @param frameworks frameworks detected from imports and annotations (Spring, Servlet, JAX-RS, ...)
 * @param sourceFiles absolute paths of the source files that will be analyzed
 * @param manifests  dependency manifests such as pom.xml or build.gradle
 * @param linesOfCode total lines across {@code sourceFiles}
 */
public record ProjectProfile(
        Path root,
        String language,
        BuildTool buildTool,
        Set<String> frameworks,
        List<Path> sourceFiles,
        List<Path> manifests,
        long linesOfCode) {

    public String relativize(Path file) {
        return root.relativize(file.toAbsolutePath().normalize()).toString().replace('\\', '/');
    }
}
