package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.tools.ScannerAdapter;
import ca.carleton.secpipe.util.SourceText;

import java.util.ArrayList;
import java.util.List;

/** Detects risky code patterns by running every selected source-code (SAST) analyzer. */
public class CodePatternAgent implements Agent {

    private final List<ScannerAdapter> adapters;

    public CodePatternAgent(List<ScannerAdapter> adapters) {
        this.adapters = adapters.stream().filter(a -> a.category() == Category.CODE).toList();
    }

    @Override
    public String name() {
        return "code-pattern";
    }

    @Override
    public String role() {
        return "Runs SAST analyzers (built-in rules, PMD, Semgrep) and normalizes their findings.";
    }

    @Override
    public void run(ScanContext ctx, PipelineState state) {
        if (adapters.isEmpty()) return;
        PipelineState local = new PipelineState();
        AdapterRunner.runAll(ctx, local, adapters);
        SourceText sources = new SourceText(ctx.root());
        List<Finding> found = new ArrayList<>(local.findings());
        for (Finding f : found) {
            if ((f.getSnippet() == null || f.getSnippet().isBlank()) && f.getLine() > 0) {
                f.setSnippet(sources.line(f.getFile(), f.getLine()));
            }
        }
        state.findings().addAll(found);
        state.toolRuns().addAll(local.toolRuns());
    }
}
