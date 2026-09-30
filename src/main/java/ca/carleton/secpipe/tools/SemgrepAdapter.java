package ca.carleton.secpipe.tools;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ProjectProfile;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.util.Json;
import ca.carleton.secpipe.util.Proc;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Semgrep CLI, used automatically when it is installed. */
public class SemgrepAdapter implements ScannerAdapter {

    private static final Pattern CWE = Pattern.compile("CWE-\\d+");

    @Override
    public String id() {
        return "semgrep";
    }

    @Override
    public String displayName() {
        return "Semgrep (" + config() + ")";
    }

    @Override
    public Category category() {
        return Category.CODE;
    }

    @Override
    public boolean isAvailable() {
        return exe().isPresent();
    }

    @Override
    public String unavailableReason() {
        return "semgrep not on PATH (optional: pipx install semgrep)";
    }

    @Override
    public String detail() {
        return exe().map(Path::toString).orElse("not installed");
    }

    @Override
    public boolean supports(ProjectProfile profile) {
        return "java".equals(profile.language());
    }

    private static Optional<Path> exe() {
        return Proc.which("semgrep");
    }

    private static String config() {
        String c = System.getenv("SECPIPE_SEMGREP_CONFIG");
        return c == null || c.isBlank() ? "p/java" : c;
    }

    @Override
    public List<Finding> run(ScanContext ctx) throws ScanException {
        if (ctx.config().isOffline() && config().startsWith("p/")) {
            throw new ScanException("offline mode: registry ruleset " + config()
                    + " needs network (set SECPIPE_SEMGREP_CONFIG to a local rules file)");
        }
        List<String> cmd = new ArrayList<>(List.of(exe().orElseThrow().toString(), "scan", "--config", config(),
                "--json", "--quiet", "--metrics", "off", "--timeout", "30",
                "--exclude", "target", "--exclude", "build", "--exclude", "secpipe-out"));
        if (!ctx.config().isIncludeTests()) cmd.addAll(List.of("--exclude", "src/test"));
        cmd.add(".");
        Proc.Result r;
        try {
            r = Proc.run(cmd, ctx.root(), Duration.ofMinutes(15));
        } catch (IOException e) {
            throw new ScanException("could not start semgrep: " + e.getMessage(), e);
        }
        if (r.timedOut()) throw new ScanException("semgrep timed out after 15 minutes");
        if (r.stdout().isBlank()) {
            throw new ScanException("semgrep exited with code " + r.exitCode() + ": " + firstLine(r.stderr()));
        }
        try {
            return parse(Json.MAPPER.readTree(r.stdout()), ctx);
        } catch (IOException e) {
            throw new ScanException("could not parse semgrep output: " + e.getMessage(), e);
        }
    }

    List<Finding> parse(JsonNode root, ScanContext ctx) {
        List<Finding> out = new ArrayList<>();
        for (JsonNode r : root.path("results")) {
            String path = r.path("path").asText().replace('\\', '/');
            if (path.startsWith("./")) path = path.substring(2);
            JsonNode extra = r.path("extra");
            JsonNode meta = extra.path("metadata");
            String checkId = r.path("check_id").asText();
            Finding f = Finding.code(id(), "semgrep:" + shortRule(checkId), path, r.path("start").path("line").asInt());
            f.setMessage(extra.path("message").asText());
            f.setSeverity(Severity.parse(extra.path("severity").asText()));
            f.setConfidence(switch (meta.path("confidence").asText("MEDIUM").toUpperCase()) {
                case "HIGH" -> Confidence.HIGH;
                case "LOW" -> Confidence.LOW;
                default -> Confidence.MEDIUM;
            });
            JsonNode cwe = meta.path("cwe");
            (cwe.isArray() ? cwe : List.of(cwe)).forEach(n -> {
                Matcher m = CWE.matcher(n.asText());
                if (m.find()) f.addCwe(m.group());
            });
            String lines = extra.path("lines").asText("");
            if (!lines.isBlank() && !lines.contains("requires login")) f.setSnippet(lines.strip().lines().findFirst().orElse(""));
            JsonNode refs = meta.path("references");
            if (refs.isArray()) refs.forEach(n -> f.addReference(n.asText()));
            f.setTitle(humanize(shortRule(checkId)));
            out.add(f);
        }
        return out;
    }

    private static String shortRule(String checkId) {
        int i = checkId.lastIndexOf('.');
        return i >= 0 ? checkId.substring(i + 1) : checkId;
    }

    private static String humanize(String rule) {
        String s = rule.replace('-', ' ').replace('_', ' ');
        return s.isEmpty() ? s : Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    private static String firstLine(String s) {
        return s == null ? "" : s.strip().lines().findFirst().orElse("");
    }
}
