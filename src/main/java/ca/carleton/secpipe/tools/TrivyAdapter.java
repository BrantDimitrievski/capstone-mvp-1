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

/** Aqua Trivy filesystem scan (dependencies only), used when installed. */
public class TrivyAdapter implements ScannerAdapter {

    @Override
    public String id() {
        return "trivy";
    }

    @Override
    public String displayName() {
        return "Trivy (filesystem, vuln scanner)";
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
        return "trivy not on PATH (optional: https://trivy.dev)";
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
        return Proc.which("trivy");
    }

    @Override
    public List<Finding> run(ScanContext ctx) throws ScanException {
        List<String> cmd = new ArrayList<>(List.of(exe().orElseThrow().toString(), "fs", "--scanners", "vuln",
                "--format", "json", "--quiet", "--skip-dirs", "secpipe-out"));
        if (ctx.config().isOffline()) cmd.addAll(List.of("--skip-db-update", "--offline-scan"));
        cmd.add(ctx.root().toString());
        try {
            Proc.Result r = Proc.run(cmd, ctx.root(), Duration.ofMinutes(15));
            if (r.timedOut()) throw new ScanException("trivy timed out");
            if (!r.ok() || r.stdout().isBlank()) {
                throw new ScanException("trivy exited with code " + r.exitCode() + ": " + r.stderr().strip().lines().findFirst().orElse(""));
            }
            return parse(Json.MAPPER.readTree(r.stdout()));
        } catch (IOException e) {
            throw new ScanException("could not run trivy: " + e.getMessage(), e);
        }
    }

    List<Finding> parse(JsonNode root) {
        List<Finding> out = new ArrayList<>();
        for (JsonNode result : root.path("Results")) {
            String target = result.path("Target").asText("pom.xml");
            for (JsonNode v : result.path("Vulnerabilities")) {
                String pkg = v.path("PkgName").asText();
                int colon = pkg.indexOf(':');
                String group = colon > 0 ? pkg.substring(0, colon) : "";
                String artifact = colon > 0 ? pkg.substring(colon + 1) : pkg;
                String fixed = v.path("FixedVersion").asText("");
                DependencyRef dep = new DependencyRef(group, artifact, v.path("InstalledVersion").asText(),
                        fixed.isBlank() ? null : fixed.split(",")[0].strip());
                String id = v.path("VulnerabilityID").asText();
                Finding f = Finding.dependency(id(), id, dep, target);
                if (id.startsWith("CVE-")) f.addCve(id);
                f.setSeverity(Severity.parse(v.path("Severity").asText()));
                f.setConfidence(Confidence.HIGH);
                f.setTitle(v.path("Title").asText("Known vulnerability in " + artifact));
                f.setMessage(dep.coordinates() + " is affected by " + id + "."
                        + (dep.fixedVersion() == null ? "" : " Fixed in " + dep.fixedVersion() + "."));
                v.path("CweIDs").forEach(c -> f.addCwe(c.asText()));
                String url = v.path("PrimaryURL").asText("");
                if (!url.isBlank()) f.addReference(url);
                out.add(f);
            }
        }
        return out;
    }
}
