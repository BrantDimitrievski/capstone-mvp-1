package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.DependencyRef;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanResult;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * One row per finding, in Excel's CSV dialect with a UTF-8 BOM so it opens with correct columns and
 * characters without any manual import steps (FR2).
 */
public class CsvReporter implements ReportWriter {

    static final String[] HEADERS = {
            "ID", "Severity", "Score", "Confidence", "Exploitability", "Category", "Title", "CWE", "OWASP Top 10",
            "CVE", "Advisory", "File", "Line", "Package", "Installed Version", "Fixed Version", "Tools",
            "Message", "Exploitability Rationale", "Suggested Fix", "Generated Test", "Fingerprint"};

    @Override
    public String format() {
        return "csv";
    }

    @Override
    public Path write(ScanResult result, Path outDir) throws IOException {
        Path file = outDir.resolve("findings.csv");
        try (Writer w = new OutputStreamWriter(Files.newOutputStream(file), StandardCharsets.UTF_8)) {
            w.write('\ufeff');
            CSVFormat format = CSVFormat.EXCEL.builder().setHeader(HEADERS).get();
            try (CSVPrinter csv = new CSVPrinter(w, format)) {
                for (Finding f : result.getFindings()) {
                    DependencyRef d = f.getDependency();
                    csv.printRecord(
                            f.getId(),
                            f.getSeverity(),
                            f.getScore(),
                            f.getConfidence(),
                            f.getExploitability().verdict(),
                            f.getCategory() == ca.carleton.secpipe.core.Category.CODE ? "Code" : "Dependency",
                            oneLine(f.getTitle()),
                            String.join(" ", f.getCwes()),
                            nz(f.getOwasp()),
                            String.join(" ", f.getCves()),
                            nz(f.getVulnerabilityId()),
                            nz(f.getFile()),
                            f.getLine() > 0 ? f.getLine() : "",
                            d == null ? "" : d.packageName(),
                            d == null ? "" : d.version(),
                            d == null || d.fixedVersion() == null ? "" : d.fixedVersion(),
                            String.join(" ", f.getTools()),
                            oneLine(f.getMessage()),
                            oneLine(f.getExploitability().rationale()),
                            nz(f.getFix()),
                            nz(f.getGeneratedTest()),
                            nz(f.getFingerprint()));
                }
            }
        }
        return file;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String oneLine(String s) {
        return s == null ? "" : s.replaceAll("\\s*\\R\\s*", " ").strip();
    }
}
