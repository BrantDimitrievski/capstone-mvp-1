package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.tools.ScannerAdapter;

import java.util.List;

/** Checks third-party dependencies against vulnerability databases (OSV, and Trivy/Grype when installed). */
public class DependencyAgent implements Agent {

    private final List<ScannerAdapter> adapters;

    public DependencyAgent(List<ScannerAdapter> adapters) {
        this.adapters = adapters.stream().filter(a -> a.category() == Category.DEPENDENCIES).toList();
    }

    @Override
    public String name() {
        return "dependency";
    }

    @Override
    public String role() {
        return "Resolves dependencies and looks up known CVEs/advisories and fixed versions.";
    }

    @Override
    public void run(ScanContext ctx, PipelineState state) {
        if (adapters.isEmpty()) return;
        AdapterRunner.runAll(ctx, state, adapters);
    }
}
