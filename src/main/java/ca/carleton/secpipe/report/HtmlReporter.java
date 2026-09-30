package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.knowledge.KnowledgeBase;
import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Self-contained, single-file HTML dashboard. The scan result is embedded as JSON and rendered in the
 * browser with textContent only, so code snippets from the scanned project can never inject markup.
 */
public class HtmlReporter implements ReportWriter {

    private static final String PLACEHOLDER = "\"__SECPIPE_DATA__\"";

    @Override
    public String format() {
        return "html";
    }

    @Override
    public Path write(ScanResult r, Path outDir) throws IOException {
        Path file = outDir.resolve("report.html");
        Files.writeString(file, render(r), StandardCharsets.UTF_8);
        return file;
    }

    String render(ScanResult r) throws IOException {
        String template;
        try (InputStream in = HtmlReporter.class.getResourceAsStream("/report/report-template.html")) {
            if (in == null) throw new IOException("missing /report/report-template.html");
            template = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        ObjectNode data = Json.MAPPER.valueToTree(r);
        ObjectNode owasp = data.putObject("owaspCatalog");
        KnowledgeBase.load().owaspCategories().forEach((id, c) -> owasp.put(id, c.name()));
        String json = Json.MAPPER.writeValueAsString(data)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029");
        String title = r.getProject() == null ? "secpipe report" : "Security report: " + r.getProject().name();
        return template.replace("__SECPIPE_TITLE__", escapeHtml(title)).replace(PLACEHOLDER, json);
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
