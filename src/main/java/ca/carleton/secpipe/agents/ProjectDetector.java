package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.BuildTool;
import ca.carleton.secpipe.util.Proc;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** File-system level detection: build tool, manifests and source files. */
public final class ProjectDetector {

    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", ".svn", ".hg", ".idea", ".vscode", ".gradle", ".mvn", "target", "build", "out", "bin",
            "node_modules", "secpipe-out", ".settings", "generated-tests");

    private static final Set<String> MANIFEST_NAMES = Set.of(
            "pom.xml", "build.gradle", "build.gradle.kts");

    private ProjectDetector() {
    }

    public static BuildTool detectBuildTool(Path root) {
        boolean pom = Files.isRegularFile(root.resolve("pom.xml"));
        boolean gradle = Files.isRegularFile(root.resolve("build.gradle"))
                || Files.isRegularFile(root.resolve("build.gradle.kts"))
                || Files.isRegularFile(root.resolve("settings.gradle"))
                || Files.isRegularFile(root.resolve("settings.gradle.kts"));
        if (pom) {
            return hasWrapper(root, "mvnw") ? BuildTool.MAVEN_WRAPPER : BuildTool.MAVEN;
        }
        if (gradle) {
            return hasWrapper(root, "gradlew") ? BuildTool.GRADLE_WRAPPER : BuildTool.GRADLE;
        }
        return BuildTool.NONE;
    }

    public static boolean hasWrapper(Path root, String name) {
        return Files.isRegularFile(root.resolve(name)) || Files.isRegularFile(root.resolve(name + ".cmd"))
                || Files.isRegularFile(root.resolve(name + ".bat"));
    }

    /** Command used to invoke the project's build tool, or null if nothing usable is available. */
    public static List<String> buildCommand(Path root, BuildTool tool) {
        switch (tool) {
            case MAVEN_WRAPPER: {
                Path w = root.resolve(Proc.isWindows() ? "mvnw.cmd" : "mvnw");
                if (Files.isRegularFile(w)) {
                    return Proc.isWindows() ? List.of(w.toString()) : List.of("sh", w.toString());
                }
                return Proc.which("mvn").map(p -> List.of(p.toString())).orElse(null);
            }
            case MAVEN:
                return Proc.which("mvn").map(p -> List.of(p.toString())).orElse(null);
            case GRADLE_WRAPPER: {
                Path w = root.resolve(Proc.isWindows() ? "gradlew.bat" : "gradlew");
                if (Files.isRegularFile(w)) {
                    return Proc.isWindows() ? List.of(w.toString()) : List.of("sh", w.toString());
                }
                return Proc.which("gradle").map(p -> List.of(p.toString())).orElse(null);
            }
            case GRADLE:
                return Proc.which("gradle").map(p -> List.of(p.toString())).orElse(null);
            default:
                return null;
        }
    }

    public static List<Path> findManifests(Path root) throws IOException {
        List<Path> out = new ArrayList<>();
        walk(root, file -> {
            if (MANIFEST_NAMES.contains(file.getFileName().toString())) out.add(file);
        });
        out.sort(null);
        return out;
    }

    public static List<Path> findSources(Path root, String extension, boolean includeTests) throws IOException {
        List<Path> out = new ArrayList<>();
        walk(root, file -> {
            if (!file.getFileName().toString().endsWith(extension)) return;
            if (!includeTests && isTestSource(root.relativize(file))) return;
            out.add(file);
        });
        out.sort(null);
        return out;
    }

    static boolean isTestSource(Path relative) {
        String p = relative.toString().replace('\\', '/');
        return p.contains("src/test/") || p.startsWith("test/") || p.contains("/test/java/")
                || p.contains("src/integrationTest/") || p.contains("src/it/");
    }

    private interface FileConsumer {
        void accept(Path file);
    }

    private static void walk(Path root, FileConsumer consumer) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root) && IGNORED_DIRS.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isRegularFile()) consumer.accept(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
