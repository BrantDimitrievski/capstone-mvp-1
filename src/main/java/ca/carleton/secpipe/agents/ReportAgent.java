package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.SecPipeException;
import ca.carleton.secpipe.report.ReportWriter;
import ca.carleton.secpipe.report.Reports;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Collects all agent outputs into the unified report in every requested format (FR2, FR6). */
public class ReportAgent implements Agent {

    private final ScanResult result;

    public ReportAgent(ScanResult result) {
        this.result = result;
    }

    @Override
    public String name() {
        return "report";
    }

    @Override
    public String role() {
        return "Writes the unified report (HTML dashboard, Markdown, CSV, JSON, SARIF).";
    }

    @Override
    public void run(ScanContext ctx, PipelineState state) throws SecPipeException {
        Path out = ctx.config().getOutDir();
        try {
            Files.createDirectories(out);
        } catch (IOException e) {
            throw new SecPipeException("cannot create output directory " + out + ": " + e.getMessage(),
                    "choose a writable location with --out.");
        }
        for (ReportWriter w : Reports.ALL) {
            if (!ctx.config().getFormats().contains(w.format())) continue;
            try {
                state.reports().add(w.write(result, out));
            } catch (IOException e) {
                throw new SecPipeException("could not write the " + w.format() + " report: " + e.getMessage(),
                        "check free disk space and permissions for " + out + ".");
            }
        }
    }
}
