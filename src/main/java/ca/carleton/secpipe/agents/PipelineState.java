package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ToolRun;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Mutable state passed between agents during one scan. */
public class PipelineState {

    private final List<Finding> findings = Collections.synchronizedList(new ArrayList<>());
    private final List<ToolRun> toolRuns = Collections.synchronizedList(new ArrayList<>());
    private final List<String> generatedTests = Collections.synchronizedList(new ArrayList<>());
    private final List<Path> reports = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Long> timings = Collections.synchronizedMap(new LinkedHashMap<>());

    public List<Finding> findings() {
        return findings;
    }

    public void replaceFindings(List<Finding> updated) {
        synchronized (findings) {
            findings.clear();
            findings.addAll(updated);
        }
    }

    public List<ToolRun> toolRuns() {
        return toolRuns;
    }

    public List<String> generatedTests() {
        return generatedTests;
    }

    public List<Path> reports() {
        return reports;
    }

    public Map<String, Long> timings() {
        return timings;
    }
}
