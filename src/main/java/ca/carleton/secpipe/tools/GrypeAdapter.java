package ca.carleton.secpipe.tools;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.DependencyRef;
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

/** Anchore Grype directory scan, used when installed. */
public class GrypeAdapter implements ScannerAdapter {

    @Override
    public String id() {
        return "grype";
    }

    @Override
    public String displayName() {
        return "Grype (directory scan)";
    }

    @Override
    public Category category() {
        return Category.DEPENDENCIES;
    }

    @Override
    public boolean isAvailable() {
        return exe().isPresent();
    }

    @Override
    public String unavailableReason() {
        return "grype not on PATH (optional: https://github.com/anchore/grype)";
    }

    @Override
    public String detail() {
        return exe().map(Path::toString).orElse("not installed");
    }

    @Override
    public boolean supports(ProjectProfile profile) {
        return !profile.manifests().isEmpty();
    }

    private static Optional<Path> exe() {
        return Proc.which("grype");
    }

    @Override
    public List<Finding> run(ScanContext ctx) throws ScanException {
        List<String> cmd = List.of(exe().orElseThrow().toString(), "dir:" + ctx.root(), "-o", "json", "-q");
        try {
            Proc.Result r = Proc.run(cmd, ctx.root(), Duration.ofMinutes(15));
            if (r.timedOut()) throw new ScanException("grype timed out");
            if (r.stdout().isBlank()) {
                throw new ScanException("grype exited with code " + r.exitCode() + ": " + r.stderr().strip().lines().findFirst().orElse(""));
            }
            return parse(Json.MAPPER.readTree(r.stdout()), ctx);
        } catch (IOException e) {
            throw new ScanException("could not run grype: " + e.getMessage(), e);
        }
    }

    List<Finding> parse(JsonNode root, ScanContext ctx) {
        List<Finding> out = new ArrayList<>();
        for (JsonNode m : root.path("matches")) {
            JsonNode v = m.path("vulnerability");
            JsonNode a = m.path("artifact");
            String group = a.path("metadata").path("pomGroupID").asText("");
            JsonNode fixes = v.path("fix").path("versions");
            DependencyRef dep = new DependencyRef(group, a.path("name").asText(), a.path("version").asText(),
                    fixes.isArray() && !fixes.isEmpty() ? fixes.get(0).asText() : null);
            String id = v.path("id").asText();
            String manifest = a.path("locations").path(0).path("path").asText("pom.xml");
            if (manifest.startsWith("/")) {
                try {
                    manifest = ctx.profile().relativize(Path.of(manifest));
                } catch (IllegalArgumentException ignored) {
                    manifest = manifest.substring(1);
                }
            }
            Finding f = Finding.dependency(id(), id, dep, manifest);
            if (id.startsWith("CVE-")) f.addCve(id);
            m.path("relatedVulnerabilities").forEach(r -> {
                if (r.path("id").asText().startsWith("CVE-")) f.addCve(r.path("id").asText());
            });
            f.setSeverity(Severity.parse(v.path("severity").asText()));
            f.setConfidence(Confidence.HIGH);
            f.setTitle(v.path("description").asText("Known vulnerability in " + dep.artifact()).lines().findFirst().orElse(""));
            f.setMessage(dep.coordinates() + " is affected by " + id + "."
                    + (dep.fixedVersion() == null ? "" : " Fixed in " + dep.fixedVersion() + "."));
            String url = v.path("dataSource").asText("");
            if (!url.isBlank()) f.addReference(url);
            out.add(f);
        }
        return out;
    }
}
