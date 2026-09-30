package ca.carleton.secpipe.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Runs external tools with a timeout and captures their output. */
public final class Proc {

    public record Result(int exitCode, String stdout, String stderr, boolean timedOut) {
        public boolean ok() {
            return !timedOut && exitCode == 0;
        }
    }

    private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");

    private Proc() {
    }

    public static boolean isWindows() {
        return WINDOWS;
    }

    /** Finds an executable on PATH, honouring Windows extensions. */
    public static Optional<Path> which(String name) {
        String path = System.getenv("PATH");
        if (path == null) return Optional.empty();
        List<String> names = new ArrayList<>();
        names.add(name);
        if (WINDOWS) {
            for (String ext : List.of(".exe", ".cmd", ".bat")) names.add(name + ext);
        }
        for (String dir : path.split(File.pathSeparator)) {
            if (dir.isBlank()) continue;
            for (String n : names) {
                Path candidate = Path.of(dir, n);
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    public static Result run(List<String> command, Path workDir, Duration timeout) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
        if (workDir != null) pb.directory(workDir.toFile());
        Process p = pb.start();
        p.getOutputStream().close();
        CompletableFuture<String> out = CompletableFuture.supplyAsync(() -> drain(p.getInputStream()));
        CompletableFuture<String> err = CompletableFuture.supplyAsync(() -> drain(p.getErrorStream()));
        try {
            boolean finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                p.descendants().forEach(ProcessHandle::destroyForcibly);
                p.destroyForcibly();
                return new Result(-1, out.getNow(""), err.getNow(""), true);
            }
            return new Result(p.exitValue(), out.join(), err.join(), false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            throw new IOException("interrupted while running " + command.get(0), e);
        }
    }

    /** First line of {@code <tool> <versionFlag>}, or empty if the tool cannot run. */
    public static Optional<String> version(Path exe, String versionFlag) {
        try {
            Result r = run(List.of(exe.toString(), versionFlag), null, Duration.ofSeconds(20));
            String text = (r.stdout() + "\n" + r.stderr()).strip();
            if (r.timedOut() || text.isEmpty()) return Optional.empty();
            return Optional.of(text.lines().findFirst().orElse("").strip());
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private static String drain(InputStream in) {
        try (in) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}
