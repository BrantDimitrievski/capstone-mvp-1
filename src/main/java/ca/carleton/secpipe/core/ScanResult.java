package ca.carleton.secpipe.core;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The unified output of a scan. Serialized as report.json, which is also the baseline for {@code verify}. */
public class ScanResult {

    public record ProjectSummary(
            String name,
            String root,
            String language,
            String buildTool,
            List<String> frameworks,
            int sourceFiles,
            long linesOfCode,
            int classes,
            int methods,
            int httpEndpoints,
            int dependencies) {
    }

    public record ScanSettings(String scope, boolean aiEnabled, String llmModel, List<String> tools, boolean includeTests) {
    }

    private String tool = "secpipe";
    private String version;
    private String startedAt;
    private long durationMs;
    private ProjectSummary project;
    private ScanSettings settings;
    private List<ToolRun> toolRuns = new ArrayList<>();
    private Map<String, Long> stageTimingsMs = new LinkedHashMap<>();
    private List<Finding> findings = new ArrayList<>();
    private List<String> generatedTests = new ArrayList<>();

    public Map<Severity, Integer> countsBySeverity() {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) counts.put(s, 0);
        findings.forEach(f -> counts.merge(f.getSeverity(), 1, Integer::sum));
        return counts;
    }

    public long count(Category category) {
        return findings.stream().filter(f -> f.getCategory() == category).count();
    }

    public String getTool() { return tool; }
    public void setTool(String tool) { this.tool = tool; }
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public String getStartedAt() { return startedAt; }
    public void setStartedAt(String startedAt) { this.startedAt = startedAt; }
    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }
    public ProjectSummary getProject() { return project; }
    public void setProject(ProjectSummary project) { this.project = project; }
    public ScanSettings getSettings() { return settings; }
    public void setSettings(ScanSettings settings) { this.settings = settings; }
    public List<ToolRun> getToolRuns() { return toolRuns; }
    public void setToolRuns(List<ToolRun> toolRuns) { this.toolRuns = new ArrayList<>(toolRuns); }
    public Map<String, Long> getStageTimingsMs() { return stageTimingsMs; }
    public void setStageTimingsMs(Map<String, Long> m) { this.stageTimingsMs = new LinkedHashMap<>(m); }
    public List<Finding> getFindings() { return findings; }
    public void setFindings(List<Finding> findings) { this.findings = new ArrayList<>(findings); }
    public List<String> getGeneratedTests() { return generatedTests; }
    public void setGeneratedTests(List<String> generatedTests) { this.generatedTests = new ArrayList<>(generatedTests); }
}
