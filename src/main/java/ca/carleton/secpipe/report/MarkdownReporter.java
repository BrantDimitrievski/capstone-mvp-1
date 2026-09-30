package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.core.ToolRun;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Developer-friendly report that renders well on GitHub and in IDEs. */
public class MarkdownReporter implements ReportWriter {

    @Override
    public String format() {
        return "md";
    }

    @Override
    public Path write(ScanResult r, Path outDir) throws IOException {
        Path file = outDir.resolve("report.md");
        Files.writeString(file, render(r), StandardCharsets.UTF_8);
        return file;
    }

    String render(ScanResult r) {
        StringBuilder md = new StringBuilder();
        ScanResult.ProjectSummary p = r.getProject();
        md.append("# Security report: ").append(p.name()).append("\n\n");
        md.append("Scanned `").append(p.root()).append("` on ").append(r.getStartedAt()).append(" with secpipe ")
                .append(r.getVersion()).append(" in ").append(Reports.formatDuration(r.getDurationMs())).append(".\n\n");

        md.append("## Summary\n\n");
        Map<Severity, Integer> counts = r.countsBySeverity();
        md.append("| Critical | High | Medium | Low | Info | Total |\n|---:|---:|---:|---:|---:|---:|\n");
        md.append("| ").append(counts.get(Severity.CRITICAL)).append(" | ").append(counts.get(Severity.HIGH)).append(" | ")
                .append(counts.get(Severity.MEDIUM)).append(" | ").append(counts.get(Severity.LOW)).append(" | ")
                .append(counts.get(Severity.INFO)).append(" | **").append(r.getFindings().size()).append("** |\n\n");
        md.append("- **Code findings:** ").append(r.count(Category.CODE)).append("\n");
        md.append("- **Dependency findings:** ").append(r.count(Category.DEPENDENCIES)).append("\n");
        md.append("- **Project:** ").append(p.language()).append(", ").append(p.buildTool()).append(", ")
                .append(p.sourceFiles()).append(" source files (").append(String.format("%,d", p.linesOfCode())).append(" lines), ")
                .append(p.classes()).append(" classes, ").append(p.httpEndpoints()).append(" HTTP endpoints, ")
                .append(p.dependencies()).append(" dependencies\n");
        if (!p.frameworks().isEmpty()) md.append("- **Frameworks:** ").append(String.join(", ", p.frameworks())).append("\n");
        md.append("- **AI assistance:** ").append(r.getSettings().aiEnabled() ? "on (" + r.getSettings().llmModel() + ")" : "off").append("\n");
        if (!r.getGeneratedTests().isEmpty()) {
            md.append("- **Generated regression tests:** ").append(r.getGeneratedTests().size()).append(" file(s) in `generated-tests/`\n");
        }
        md.append("\n");

        if (!r.getFindings().isEmpty()) {
            md.append("## Findings\n\n");
            md.append("| ID | Severity | Score | Finding | OWASP | Location | Exploitability |\n|---|---|---:|---|---|---|---|\n");
            for (Finding f : r.getFindings()) {
                md.append("| [").append(f.getId()).append("](#").append(f.getId().toLowerCase()).append(") | ")
                        .append(f.getSeverity()).append(" | ").append(f.getScore()).append(" | ")
                        .append(cell(Reports.label(f))).append(" | ").append(cell(f.getOwasp())).append(" | `")
                        .append(cell(Reports.location(f))).append("` | ").append(f.getExploitability().verdict()).append(" |\n");
            }
            md.append("\n## Details\n\n");
            for (Finding f : r.getFindings()) details(md, f);
        } else {
            md.append("## Findings\n\nNo security findings were reported by the analyzers that ran.\n\n");
        }

        md.append("## Analyzers\n\n| Tool | Category | Status | Findings | Time | Notes |\n|---|---|---|---:|---:|---|\n");
        for (ToolRun t : r.getToolRuns()) {
            md.append("| ").append(t.tool()).append(" | ").append(t.category().name().toLowerCase()).append(" | ")
                    .append(t.status()).append(" | ").append(t.findings()).append(" | ")
                    .append(t.status() == ToolRun.Status.SKIPPED ? "-" : Reports.formatDuration(t.durationMs())).append(" | ")
                    .append(cell(t.message())).append(" |\n");
        }
        md.append("\n## Timings\n\n| Stage | Time |\n|---|---:|\n");
        r.getStageTimingsMs().forEach((k, v) -> md.append("| ").append(k).append(" | ").append(Reports.formatDuration(v)).append(" |\n"));
        md.append("\n---\n\nVerify fixes with `secpipe verify ").append(p.root()).append(" --baseline report.json`.\n");
        return md.toString();
    }

    private void details(StringBuilder md, Finding f) {
        md.append("### ").append(f.getId()).append("\n\n");
        md.append("**").append(f.getSeverity()).append("** | ").append(esc(Reports.label(f))).append(" | `")
                .append(Reports.location(f)).append("`\n\n");
        md.append("- **Category:** ").append(f.getCategory() == Category.CODE ? "Source code" : "Dependency").append("\n");
        if (f.getDependency() != null) {
            md.append("- **Package:** `").append(f.getDependency().coordinates()).append("`")
                    .append(f.getDependency().fixedVersion() == null ? " (no fix published)" : " (fixed in `" + f.getDependency().fixedVersion() + "`)")
                    .append("\n");
        }
        if (!f.getCwes().isEmpty()) md.append("- **CWE:** ").append(String.join(", ", f.getCwes().stream().map(MarkdownReporter::cweLink).toList())).append("\n");
        if (!f.getCves().isEmpty()) md.append("- **CVE:** ").append(String.join(", ", f.getCves().stream()
                .map(c -> "[" + c + "](https://nvd.nist.gov/vuln/detail/" + c + ")").toList())).append("\n");
        if (f.getVulnerabilityId() != null && !f.getCves().contains(f.getVulnerabilityId())) {
            md.append("- **Advisory:** [").append(f.getVulnerabilityId()).append("](https://osv.dev/vulnerability/")
                    .append(f.getVulnerabilityId()).append(")\n");
        }
        if (f.getOwasp() != null) md.append("- **OWASP Top 10:** ").append(f.getOwasp()).append("\n");
        md.append("- **Score:** ").append(f.getScore()).append(" / 10 (confidence ").append(f.getConfidence()).append(")\n");
        md.append("- **Exploitability:** ").append(f.getExploitability().verdict()).append(" - ")
                .append(esc(f.getExploitability().rationale())).append(" _(").append(f.getExploitability().source()).append(")_\n");
        md.append("- **Detected by:** ").append(String.join(", ", f.getTools())).append(" (`").append(f.getRuleId()).append("`)\n\n");
        if (f.getSnippet() != null && !f.getSnippet().isBlank() && f.getCategory() == Category.CODE) {
            md.append("```java\n").append(f.getSnippet()).append("\n```\n\n");
        }
        if (f.getMessage() != null) md.append(esc(f.getMessage())).append("\n\n");
        if (f.getExplanation() != null && !f.getExplanation().equals(f.getMessage())) {
            md.append("**Why it matters:** ").append(esc(f.getExplanation().replaceAll("\\s*\\R\\s*", " "))).append("\n\n");
        }
        if (f.getFix() != null) {
            md.append("**Suggested fix").append("llm".equals(f.getFixSource()) ? " (AI-assisted)" : "").append(":** ");
            md.append(fixMarkdown(f.getFix())).append("\n\n");
        }
        if (f.getGeneratedTest() != null) md.append("**Regression test:** `").append(f.getGeneratedTest()).append("`\n\n");
        if (!f.getReferences().isEmpty()) {
            md.append("<details><summary>References</summary>\n\n");
            f.getReferences().forEach(ref -> md.append("- ").append(ref).append("\n"));
            md.append("\n</details>\n\n");
        }
    }

    static String fixMarkdown(String fix) {
        int ex = fix.indexOf("\n\nExample:\n");
        if (ex < 0) return esc(fix);
        return esc(fix.substring(0, ex)) + "\n\n```java\n" + fix.substring(ex + "\n\nExample:\n".length()) + "\n```";
    }

    private static String cweLink(String cwe) {
        return "[" + cwe + "](https://cwe.mitre.org/data/definitions/" + cwe.substring(4) + ".html)";
    }

    private static String cell(String s) {
        return s == null ? "" : s.replace("|", "\\|").replaceAll("\\s*\\R\\s*", " ");
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("<", "&lt;").replace(">", "&gt;");
    }
}
