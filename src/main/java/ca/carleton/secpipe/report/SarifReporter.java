package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/** SARIF 2.1.0 output, ready for GitHub code scanning in the planned GitHub Action. */
public class SarifReporter implements ReportWriter {

    @Override
    public String format() {
        return "sarif";
    }

    @Override
    public Path write(ScanResult r, Path outDir) throws IOException {
        Path file = outDir.resolve("report.sarif");
        Json.MAPPER.writeValue(file.toFile(), build(r));
        return file;
    }

    ObjectNode build(ScanResult r) {
        ObjectNode root = Json.MAPPER.createObjectNode();
        root.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        root.put("version", "2.1.0");
        ObjectNode run = root.putArray("runs").addObject();
        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "secpipe");
        driver.put("version", r.getVersion());
        ArrayNode rules = driver.putArray("rules");
        Map<String, Integer> ruleIndex = new LinkedHashMap<>();
        ArrayNode results = run.putArray("results");

        for (Finding f : r.getFindings()) {
            String ruleId = ruleId(f);
            Integer idx = ruleIndex.get(ruleId);
            if (idx == null) {
                idx = ruleIndex.size();
                ruleIndex.put(ruleId, idx);
                ObjectNode rule = rules.addObject();
                rule.put("id", ruleId);
                rule.put("name", f.getTitle() == null ? ruleId : f.getTitle());
                rule.putObject("shortDescription").put("text", f.getTitle() == null ? ruleId : f.getTitle());
                if (f.getExplanation() != null) rule.putObject("fullDescription").put("text", f.getExplanation());
                if (f.getFix() != null) rule.putObject("help").put("text", f.getFix());
                if (!f.getReferences().isEmpty()) rule.put("helpUri", f.getReferences().get(0));
                ObjectNode props = rule.putObject("properties");
                ArrayNode tags = props.putArray("tags");
                tags.add("security");
                f.getCwes().forEach(c -> tags.add("external/cwe/" + c.toLowerCase()));
                props.put("security-severity", securitySeverity(f.getSeverity()));
            }
            ObjectNode res = results.addObject();
            res.put("ruleId", ruleId);
            res.put("ruleIndex", idx);
            res.put("level", level(f.getSeverity()));
            res.putObject("message").put("text", f.getMessage() == null ? Reports.label(f) : f.getMessage());
            ObjectNode loc = res.putArray("locations").addObject().putObject("physicalLocation");
            loc.putObject("artifactLocation").put("uri", f.getFile() == null ? "pom.xml" : f.getFile());
            loc.putObject("region").put("startLine", Math.max(1, f.getLine()));
            res.putObject("partialFingerprints").put("secpipe/v1", f.getFingerprint() == null ? f.computeFingerprint() : f.getFingerprint());
            ObjectNode props = res.putObject("properties");
            props.put("secpipeId", f.getId());
            props.put("severity", f.getSeverity().name());
            props.put("confidence", f.getConfidence().name());
            props.put("score", f.getScore());
            props.put("exploitability", f.getExploitability().verdict().name());
            if (f.getOwasp() != null) props.put("owasp", f.getOwasp());
            if (!f.getCves().isEmpty()) {
                ArrayNode cves = props.putArray("cves");
                f.getCves().forEach(cves::add);
            }
            ArrayNode tools = props.putArray("tools");
            f.getTools().forEach(tools::add);
        }
        return root;
    }

    private static String ruleId(Finding f) {
        if (f.getCategory() == Category.DEPENDENCIES) return f.primaryVulnId();
        return f.getRuleId();
    }

    private static String level(Severity s) {
        return switch (s) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    private static String securitySeverity(Severity s) {
        return switch (s) {
            case CRITICAL -> "9.5";
            case HIGH -> "8.0";
            case MEDIUM -> "5.5";
            case LOW -> "3.0";
            case INFO -> "0.0";
        };
    }
}
