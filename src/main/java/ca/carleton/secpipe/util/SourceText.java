package ca.carleton.secpipe.util;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Cached access to source lines for snippets and code windows. */
public final class SourceText {

    private final Path root;
    private final Map<String, List<String>> cache = new ConcurrentHashMap<>();

    public SourceText(Path root) {
        this.root = root;
    }

    public static List<String> readLines(Path file) {
        try {
            return Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            try {
                return Files.readAllLines(file, StandardCharsets.ISO_8859_1);
            } catch (IOException ex) {
                return List.of();
            }
        } catch (IOException e) {
            return List.of();
        }
    }

    public List<String> lines(String relativeFile) {
        return cache.computeIfAbsent(relativeFile, f -> readLines(root.resolve(f)));
    }

    public String line(String relativeFile, int line) {
        List<String> lines = lines(relativeFile);
        if (line < 1 || line > lines.size()) return null;
        String s = lines.get(line - 1).strip();
        return s.length() > 240 ? s.substring(0, 237) + "..." : s;
    }

    /** Lines around {@code line}, prefixed with line numbers, for LLM prompts and reports. */
    public String window(String relativeFile, int line, int radius) {
        List<String> lines = lines(relativeFile);
        if (lines.isEmpty()) return "";
        int from = Math.max(1, line - radius);
        int to = Math.min(lines.size(), line + radius);
        StringBuilder sb = new StringBuilder();
        for (int i = from; i <= to; i++) {
            sb.append(String.format("%5d%s %s%n", i, i == line ? ">" : " ", lines.get(i - 1)));
        }
        return sb.toString();
    }
}
