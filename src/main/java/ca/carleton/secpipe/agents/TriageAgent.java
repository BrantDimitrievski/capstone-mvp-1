package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.Severity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * De-duplicates findings reported by several tools, then ranks them by
 * {@code score = severity weight x confidence factor x exploitability factor} (0-10).
 */
public class TriageAgent implements Agent {

    private static final Set<String> SECRET_FAMILY = Set.of("CWE-798", "CWE-321", "CWE-259");

    @Override
    public String name() {
        return "triage";
    }

    @Override
    public String role() {
        return "Merges duplicate findings across tools and ranks them by severity, confidence and exploitability.";
    }

    @Override
    public void run(ScanContext ctx, PipelineState state) {
        List<Finding> ranked;
        synchronized (state.findings()) {
            ranked = triage(state.findings());
        }
        state.replaceFindings(ranked);
    }

    public List<Finding> triage(List<Finding> input) {
        Map<String, Finding> merged = new LinkedHashMap<>();
        List<Finding> ordered = new ArrayList<>(input);
        ordered.sort(Comparator.comparing((Finding f) -> f.getTools().contains("builtin") ? 0 : 1));
        for (Finding f : ordered) {
            merged.merge(dedupeKey(f), f, TriageAgent::merge);
        }
        List<Finding> out = new ArrayList<>(merged.values());
        for (Finding f : out) {
            if (f.getTools().size() > 1) f.setConfidence(f.getConfidence().raise());
            f.setScore(score(f));
            f.setFingerprint(f.computeFingerprint());
        }
        out.sort(Comparator.comparingDouble(Finding::getScore).reversed()
                .thenComparing(Finding::getSeverity)
                .thenComparing(Finding::getCategory)
                .thenComparing(f -> f.getFile() == null ? "" : f.getFile())
                .thenComparingInt(Finding::getLine));
        for (int i = 0; i < out.size(); i++) out.get(i).setId(String.format("SP-%03d", i + 1));
        return out;
    }

    static String dedupeKey(Finding f) {
        if (f.getCategory() == Category.DEPENDENCIES) {
            String artifact = f.getDependency() == null ? "" : f.getDependency().artifact().toLowerCase(Locale.ROOT);
            String version = f.getDependency() == null ? "" : f.getDependency().version();
            return "dep|" + artifact + "|" + version + "|" + f.primaryVulnId();
        }
        String cwe = f.primaryCwe();
        String family = cwe == null ? f.getRuleId() : SECRET_FAMILY.contains(cwe) ? "secret" : cwe;
        return "code|" + f.getFile() + "|" + f.getLine() + "|" + family;
    }

    static Finding merge(Finding a, Finding b) {
        Set<String> tools = new java.util.LinkedHashSet<>(a.getTools());
        tools.addAll(b.getTools());
        a.setTools(tools);
        a.setSeverity(Severity.max(a.getSeverity(), b.getSeverity()));
        a.setConfidence(Confidence.max(a.getConfidence(), b.getConfidence()));
        b.getCwes().forEach(a::addCwe);
        b.getCves().forEach(a::addCve);
        b.getReferences().forEach(a::addReference);
        if (a.getSnippet() == null) a.setSnippet(b.getSnippet());
        if (a.getExplanation() == null) a.setExplanation(b.getExplanation());
        if (a.getFix() == null) {
            a.setFix(b.getFix());
            a.setFixSource(b.getFixSource());
        }
        if (a.getDependency() != null && a.getDependency().fixedVersion() == null && b.getDependency() != null
                && b.getDependency().fixedVersion() != null) {
            a.setDependency(a.getDependency().withFixedVersion(b.getDependency().fixedVersion()));
        }
        if ("llm".equals(b.getExploitability().source()) && !"llm".equals(a.getExploitability().source())) {
            a.setExploitability(b.getExploitability());
        }
        return a;
    }

    static double score(Finding f) {
        double raw = f.getSeverity().weight() * f.getConfidence().factor() * f.getExploitability().verdict().factor();
        return Math.round(raw * 10.0) / 10.0;
    }
}
