package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;

import java.util.List;

public final class Reports {

    public static final List<ReportWriter> ALL = List.of(
            new HtmlReporter(), new MarkdownReporter(), new JsonReporter(), new CsvReporter(), new SarifReporter());

    private Reports() {
    }

    /** Short label: "CWE-89 SQL injection" for code, "CVE-2021-44228 log4j-core 2.14.1" for dependencies. */
    public static String label(Finding f) {
        if (f.getCategory() == Category.DEPENDENCIES && f.getDependency() != null) {
            return f.primaryVulnId() + " in " + f.getDependency().artifact() + " " + f.getDependency().version();
        }
        String cwe = f.primaryCwe();
        return (cwe == null ? "" : cwe + " ") + (f.getTitle() == null ? f.getRuleId() : f.getTitle());
    }

    public static String location(Finding f) {
        if (f.getCategory() == Category.DEPENDENCIES) {
            return f.getFile() == null ? "" : f.getFile();
        }
        return f.location();
    }

    public static String formatDuration(long ms) {
        if (ms < 1000) return ms + " ms";
        if (ms < 60_000) return String.format("%.1f s", ms / 1000.0);
        return String.format("%d min %d s", ms / 60_000, (ms % 60_000) / 1000);
    }
}
