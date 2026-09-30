package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.core.ToolRun;
import ca.carleton.secpipe.util.Console;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Displays the scan result in the terminal (FR6). */
public class TerminalSummary {

    private final Console c;

    public TerminalSummary(Console console) {
        this.c = console;
    }

    public void print(ScanResult r, List<Path> reports, int top, Severity failOn) {
        Map<Severity, Integer> counts = r.countsBySeverity();
        c.println();
        c.println(c.bold("Scan complete: " + r.getFindings().size() + " finding(s) in " + Reports.formatDuration(r.getDurationMs())));
        StringBuilder row = new StringBuilder(" ");
        for (Severity s : Severity.values()) {
            row.append(' ').append(c.severity(s)).append(' ').append(counts.get(s)).append("  ");
        }
        c.println(row.toString().stripTrailing());
        c.println("  code: " + r.count(Category.CODE) + "   dependencies: " + r.count(Category.DEPENDENCIES)
                + "   project: " + r.getProject().sourceFiles() + " files, " + r.getProject().dependencies() + " dependencies");

        if (!r.getFindings().isEmpty()) {
            c.println();
            c.println(c.dim(String.format("  %-7s %-8s %5s  %-52s %s", "ID", "SEVERITY", "SCORE", "FINDING", "LOCATION")));
            int shown = 0;
            for (Finding f : r.getFindings()) {
                if (shown++ >= top) break;
                c.println(String.format("  %-7s %s %5.1f  %-52s %s", f.getId(), c.severity(f.getSeverity()), f.getScore(),
                        truncate(Reports.label(f), 52), c.dim(truncate(Reports.location(f), 70))));
            }
            if (r.getFindings().size() > top) {
                c.println(c.dim("  ... and " + (r.getFindings().size() - top) + " more in the report (use --top N to list more)"));
            }
        }

        c.println();
        String tools = r.getToolRuns().stream()
                .filter(t -> t.status() != ToolRun.Status.SKIPPED || !t.message().startsWith("category"))
                .map(t -> t.tool() + " " + switch (t.status()) {
                    case OK -> c.green("ok") + " (" + t.findings() + ")";
                    case FAILED -> c.red("failed");
                    case SKIPPED -> c.dim("skipped");
                })
                .collect(Collectors.joining(", "));
        c.println("Analyzers: " + tools);
        String timings = r.getStageTimingsMs().entrySet().stream()
                .filter(e -> !e.getKey().equals("total"))
                .map(e -> e.getKey() + " " + Reports.formatDuration(e.getValue()))
                .collect(Collectors.joining(", "));
        c.println(c.dim("Timings:   " + timings));
        if (!reports.isEmpty()) {
            c.println();
            c.println("Reports:");
            reports.forEach(p -> c.println("  " + p));
        }
        if (!r.getGeneratedTests().isEmpty()) {
            Path first = reports.isEmpty() ? null : reports.get(0).getParent();
            c.println("Regression tests: " + r.getGeneratedTests().size() + " file(s)"
                    + (first == null ? "" : " in " + first.resolve("generated-tests")));
        }
        c.println();
        if (failOn == null) {
            c.println(c.dim("Result: not gating (--fail-on none)"));
        } else {
            long gating = r.getFindings().stream().filter(f -> f.getSeverity().atLeast(failOn)).count();
            if (gating == 0) {
                c.println(c.green("Result: PASS") + c.dim(" - no findings at or above " + failOn + " (--fail-on " + failOn.name().toLowerCase() + ")"));
            } else {
                c.println(c.red("Result: FAIL") + c.dim(" - " + gating + " finding(s) at or above " + failOn
                        + " (--fail-on " + failOn.name().toLowerCase() + ")"));
            }
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 3) + "...";
    }
}
