package ca.carleton.secpipe.tools;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.DependencyRef;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ProjectProfile;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.tools.deps.Cvss3;
import ca.carleton.secpipe.tools.deps.DependencyResolver;
import ca.carleton.secpipe.tools.deps.VersionComparator;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.Set;

/** Dependency vulnerabilities (SCA) from OSV.dev: GitHub advisories, CVEs, fixed versions. */
public class OsvAdapter implements ScannerAdapter {

    public static final String DEPENDENCIES_KEY = "dependencies";

    @Override
    public String id() {
        return "osv";
    }

    @Override
    public String displayName() {
        return "OSV.dev dependency advisories";
    }

    @Override
    public Category category() {
        return Category.DEPENDENCIES;
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public String detail() {
        return "embedded client, " + OsvClient.baseUrl();
    }

    @Override
    public boolean supports(ProjectProfile profile) {
        return !profile.manifests().isEmpty();
    }

    @Override
    public List<Finding> run(ScanContext ctx) throws ScanException {
        DependencyResolver.Resolution res = new DependencyResolver().resolve(ctx);
        ctx.put(DEPENDENCIES_KEY, res);
        res.warnings().forEach(w -> ctx.console().warn(w));
        ctx.put("note:" + id(), res.dependencies().size() + " dependencies via " + res.method()
                + (ctx.config().isOffline() ? " (offline: cached advisories only)" : ""));
        if (res.dependencies().isEmpty()) return List.of();

        OsvClient client = new OsvClient(ctx.config().isOffline());
        Map<DependencyRef, List<String>> hits = client.query(res.dependencies());
        Set<String> ids = new LinkedHashSet<>();
        hits.values().forEach(ids::addAll);
        Map<String, JsonNode> details = client.details(new ArrayList<>(ids));

        List<Finding> out = new ArrayList<>();
        hits.forEach((dep, vulnIds) -> {
            for (String id : vulnIds) {
                JsonNode v = details.get(id);
                out.add(toFinding(dep, id, v, res.manifest()));
            }
        });
        return out;
    }

    Finding toFinding(DependencyRef dep, String id, JsonNode v, String manifest) {
        Finding f = Finding.dependency(id(), id, dep, manifest);
        f.setConfidence(Confidence.HIGH);
        f.addReference("https://osv.dev/vulnerability/" + id);
        if (id.startsWith("CVE-")) f.addCve(id);
        if (v == null) {
            f.setTitle("Known vulnerability in " + dep.artifact());
            f.setMessage(dep.coordinates() + " is affected by " + id + ".");
            return f;
        }
        v.path("aliases").forEach(a -> {
            if (a.asText().startsWith("CVE-")) f.addCve(a.asText());
        });
        String summary = v.path("summary").asText("");
        f.setTitle(summary.isBlank() ? "Known vulnerability in " + dep.artifact() : summary);
        String details = v.path("details").asText("");
        if (!details.isBlank()) f.setExplanation(details.length() > 1500 ? details.substring(0, 1497) + "..." : details);
        f.setSeverity(severity(v));
        v.path("database_specific").path("cwe_ids").forEach(c -> f.addCwe(c.asText()));
        String fixed = fixedVersion(v, dep);
        f.setDependency(dep.withFixedVersion(fixed));
        f.setMessage(dep.coordinates() + " is affected by " + (f.getCves().isEmpty() ? id : f.getCves().get(0) + " / " + id)
                + (summary.isBlank() ? "." : ": " + summary)
                + (fixed == null ? " No fixed version is published yet." : " Fixed in " + fixed + "."));
        int refs = 0;
        for (JsonNode r : v.path("references")) {
            if (refs++ >= 4) break;
            f.addReference(r.path("url").asText());
        }
        return f;
    }

    static Severity severity(JsonNode v) {
        String label = v.path("database_specific").path("severity").asText("");
        if (!label.isBlank()) return Severity.parse(label);
        double best = -1;
        for (JsonNode s : v.path("severity")) {
            OptionalDouble score = Cvss3.baseScore(s.path("score").asText());
            if (score.isPresent()) best = Math.max(best, score.getAsDouble());
        }
        for (JsonNode a : v.path("affected")) {
            String eco = a.path("ecosystem_specific").path("severity").asText("");
            if (!eco.isBlank() && best < 0) return Severity.parse(eco);
        }
        return best >= 0 ? Severity.fromCvss(best) : Severity.MEDIUM;
    }

    static String fixedVersion(JsonNode v, DependencyRef dep) {
        String best = null;
        String any = null;
        for (JsonNode a : v.path("affected")) {
            if (!a.path("package").path("name").asText().equalsIgnoreCase(dep.packageName())) continue;
            for (JsonNode range : a.path("ranges")) {
                for (JsonNode event : range.path("events")) {
                    String fixed = event.path("fixed").asText(null);
                    if (fixed == null) continue;
                    if (any == null) any = fixed;
                    if (VersionComparator.INSTANCE.compare(fixed, dep.version()) > 0
                            && (best == null || VersionComparator.INSTANCE.compare(fixed, best) < 0)) {
                        best = fixed;
                    }
                }
            }
        }
        return best != null ? best : any;
    }
}
