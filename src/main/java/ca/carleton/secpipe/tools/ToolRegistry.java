package ca.carleton.secpipe.tools;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.ProjectProfile;
import ca.carleton.secpipe.core.ScanConfig;
import ca.carleton.secpipe.core.ToolRun;
import ca.carleton.secpipe.tools.builtin.BuiltinRulesAdapter;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** Holds every known analyzer and decides which ones run for a given project and config. */
public class ToolRegistry {

    /** An adapter the plan will run, or the reason it will not. */
    public record Selection(ScannerAdapter adapter, boolean selected, String reason) {
        public ToolRun asSkipped() {
            return ToolRun.skipped(adapter.id(), adapter.category(), reason);
        }
    }

    private final List<ScannerAdapter> adapters = new ArrayList<>();

    public static ToolRegistry defaults() {
        return new ToolRegistry()
                .register(new BuiltinRulesAdapter())
                .register(new PmdAdapter())
                .register(new SemgrepAdapter())
                .register(new OsvAdapter())
                .register(new TrivyAdapter())
                .register(new GrypeAdapter());
    }

    public ToolRegistry register(ScannerAdapter adapter) {
        adapters.removeIf(a -> a.id().equals(adapter.id()));
        adapters.add(adapter);
        return this;
    }

    public List<ScannerAdapter> all() {
        return List.copyOf(adapters);
    }

    public Set<String> ids() {
        return adapters.stream().map(ScannerAdapter::id).collect(Collectors.toCollection(java.util.LinkedHashSet::new));
    }

    public List<Selection> plan(ProjectProfile profile, ScanConfig config) {
        Set<Category> categories = config.getScope().categories();
        List<Selection> out = new ArrayList<>();
        for (ScannerAdapter a : adapters) {
            if (!categories.contains(a.category())) {
                out.add(new Selection(a, false, "category not in scope (--category " + config.getScope().name().toLowerCase() + ")"));
            } else if (!config.getOnlyTools().isEmpty() && !config.getOnlyTools().contains(a.id())) {
                out.add(new Selection(a, false, "not listed in --tools"));
            } else if (config.getExcludeTools().contains(a.id())) {
                out.add(new Selection(a, false, "excluded with --exclude-tools"));
            } else if (!a.supports(profile)) {
                out.add(new Selection(a, false, "does not support this project"));
            } else if (!a.isAvailable()) {
                out.add(new Selection(a, false, a.unavailableReason()));
            } else {
                out.add(new Selection(a, true, "selected"));
            }
        }
        return out;
    }
}
