package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.BaselineDiff;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Writes verify.md and verify.json describing what a remediation fixed, kept or introduced. */
public class VerifyReport {

    public Path write(BaselineDiff diff, ScanResult baseline, ScanResult current, Path outDir) throws IOException {
        Files.createDirectories(outDir);
        ObjectNode json = Json.MAPPER.createObjectNode();
        json.put("baselineScan", baseline.getStartedAt());
        json.put("verificationScan", current.getStartedAt());
        json.put("fixed", diff.fixed().size());
        json.put("stillPresent", diff.stillPresent().size());
        json.put("introduced", diff.introduced().size());
        add(json.putArray("fixedFindings"), diff.fixed());
        add(json.putArray("stillPresentFindings"), diff.stillPresent());
        add(json.putArray("introducedFindings"), diff.introduced());
        Json.MAPPER.writeValue(outDir.resolve("verify.json").toFile(), json);

        StringBuilder md = new StringBuilder();
        md.append("# Remediation verification\n\n");
        md.append("Baseline scan: ").append(baseline.getStartedAt()).append("  \nVerification scan: ").append(current.getStartedAt()).append("\n\n");
        md.append("| Fixed | Still present | New |\n|---:|---:|---:|\n| ").append(diff.fixed().size()).append(" | ")
                .append(diff.stillPresent().size()).append(" | ").append(diff.introduced().size()).append(" |\n\n");
        section(md, "Fixed", diff.fixed());
        section(md, "Still present", diff.stillPresent());
        section(md, "New since baseline", diff.introduced());
        Path file = outDir.resolve("verify.md");
        Files.writeString(file, md.toString(), StandardCharsets.UTF_8);
        return file;
    }

    private static void add(ArrayNode arr, List<Finding> findings) {
        for (Finding f : findings) {
            ObjectNode n = arr.addObject();
            n.put("fingerprint", f.getFingerprint());
            n.put("severity", f.getSeverity().name());
            n.put("finding", Reports.label(f));
            n.put("location", Reports.location(f));
        }
    }

    private static void section(StringBuilder md, String title, List<Finding> findings) {
        md.append("## ").append(title).append(" (").append(findings.size()).append(")\n\n");
        if (findings.isEmpty()) {
            md.append("None.\n\n");
            return;
        }
        md.append("| Severity | Finding | Location |\n|---|---|---|\n");
        findings.forEach(f -> md.append("| ").append(f.getSeverity()).append(" | ").append(Reports.label(f).replace("|", "\\|"))
                .append(" | `").append(Reports.location(f)).append("` |\n"));
        md.append("\n");
    }
}
