package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.DependencyRef;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.knowledge.KnowledgeBase;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Maps findings to CWE entries and OWASP Top 10 categories and attaches explanations, fixes and references (FR3). */
public class KnowledgeAgent implements Agent {

    @Override
    public String name() {
        return "knowledge";
    }

    @Override
    public String role() {
        return "Enriches findings with CWE, CVE and OWASP Top 10 (2021) mappings, explanations and fixes.";
    }

    @Override
    public void run(ScanContext ctx, PipelineState state) {
        KnowledgeBase kb = ctx.knowledge();
        synchronized (state.findings()) {
            state.findings().forEach(f -> enrich(kb, f));
        }
    }

    public void enrich(KnowledgeBase kb, Finding f) {
        List<String> normalized = new ArrayList<>();
        for (String raw : f.getCwes()) KnowledgeBase.normalizeCwe(raw).filter(c -> !normalized.contains(c)).ifPresent(normalized::add);
        f.setCwes(normalized);

        Optional<KnowledgeBase.CweEntry> entry = normalized.stream().map(kb::cwe).flatMap(Optional::stream).findFirst();

        if (f.getCategory() == Category.DEPENDENCIES) {
            if (f.getOwasp() == null) f.setOwasp(kb.vulnerableComponents().label());
            f.addReference(kb.vulnerableComponents().url());
            if (f.getFix() == null) {
                f.setFix(dependencyFix(f.getDependency()));
                f.setFixSource("catalog");
            }
            if (f.getExplanation() == null) {
                f.setExplanation("A known vulnerability affects this dependency version"
                        + entry.map(e -> " (" + e.id() + ": " + e.name() + ")").orElse("") + ".");
            }
        } else {
            if (f.getOwasp() == null) {
                normalized.stream().map(kb::owaspFor).flatMap(Optional::stream).findFirst()
                        .ifPresent(o -> {
                            f.setOwasp(o.label());
                            f.addReference(o.url());
                        });
            }
            entry.ifPresent(e -> {
                if (f.getTitle() == null || f.getTitle().isBlank()) f.setTitle(e.name());
                if (f.getExplanation() == null) f.setExplanation(e.description());
                if (f.getFix() == null) {
                    f.setFix(e.fix() + (e.example() == null ? "" : "\n\nExample:\n" + e.example()));
                    f.setFixSource("catalog");
                }
            });
            if (f.getTitle() == null || f.getTitle().isBlank()) f.setTitle(f.getRuleId());
            if (f.getExplanation() == null) f.setExplanation(f.getMessage());
            if (f.getFix() == null) {
                f.setFix("Review the flagged code and apply the analyzer's recommendation.");
                f.setFixSource("catalog");
            }
        }
        entry.ifPresent(e -> f.addReference(e.url()));
        normalized.forEach(c -> {
            if (kb.cwe(c).isEmpty()) f.addReference("https://cwe.mitre.org/data/definitions/" + c.substring(4) + ".html");
        });
        f.getCves().forEach(cve -> f.addReference("https://nvd.nist.gov/vuln/detail/" + cve));
    }

    private static String dependencyFix(DependencyRef dep) {
        if (dep == null) return "Upgrade the affected dependency to a patched version.";
        if (dep.fixedVersion() != null) {
            return "Upgrade " + dep.packageName() + " from " + dep.version() + " to " + dep.fixedVersion()
                    + " or later. If it is a transitive dependency, pin the version in <dependencyManagement> "
                    + "(Maven) or a constraints block (Gradle).";
        }
        return "No patched release of " + dep.packageName() + " is listed yet. Check the advisory for mitigations, "
                + "restrict use of the affected feature, or replace the library.";
    }
}
