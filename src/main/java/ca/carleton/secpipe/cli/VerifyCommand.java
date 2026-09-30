package ca.carleton.secpipe.cli;

import ca.carleton.secpipe.agents.OrchestratorAgent;
import ca.carleton.secpipe.core.BaselineDiff;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanConfig;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.SecPipeException;
import ca.carleton.secpipe.report.VerifyReport;
import ca.carleton.secpipe.tools.ToolRegistry;
import ca.carleton.secpipe.util.Console;
import ca.carleton.secpipe.util.Json;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(name = "verify", mixinStandardHelpOptions = true,
        description = {
                "Re-scan a project after remediation and compare it with a baseline report.json.",
                "Each baseline finding is reported as fixed or still present; anything else is new.",
                "Exit codes: 0 = nothing at/above --fail-on remains or was introduced, 1 = otherwise, 2 = error."
        })
public class VerifyCommand implements Callable<Integer> {

    @Parameters(index = "0", defaultValue = ".", paramLabel = "PATH", description = "Project root to re-scan.")
    Path target;

    @Option(names = {"-b", "--baseline"}, required = true, paramLabel = "REPORT_JSON",
            description = "report.json from an earlier 'secpipe scan'.")
    Path baseline;

    @Option(names = {"-o", "--out"}, defaultValue = "secpipe-out/verify", paramLabel = "DIR",
            description = "Output directory for the re-scan and the verification report. Default: ${DEFAULT-VALUE}.")
    Path out;

    @Mixin
    ScanOptions options;

    @Override
    public Integer call() throws Exception {
        ScanResult before = loadBaseline(baseline);
        ScanConfig config = options.toConfig(target, out);
        if (options.formats == null || options.formats.isEmpty()) config.setFormats(Set.of("json", "md"));
        config.setGenerateTests(false);
        if (options.tools == null && before.getSettings() != null && before.getSettings().tools() != null) {
            config.setOnlyTools(Set.copyOf(before.getSettings().tools()));
        }

        Console console = Console.system(options.quiet, options.verbose);
        OrchestratorAgent.Outcome outcome = new OrchestratorAgent(ToolRegistry.defaults(), console).execute(config);
        BaselineDiff diff = BaselineDiff.compare(before, outcome.result());
        Path report = new VerifyReport().write(diff, before, outcome.result(), config.getOutDir());

        print(console, diff, report);
        return diff.passes(config.getFailOn()) ? SecPipeCli.EXIT_OK : SecPipeCli.EXIT_FINDINGS;
    }

    static ScanResult loadBaseline(Path file) throws SecPipeException {
        if (!Files.isRegularFile(file)) {
            throw new SecPipeException("baseline not found: " + file,
                    "run 'secpipe scan <path>' first and pass its secpipe-out/report.json with --baseline.");
        }
        try {
            ScanResult r = Json.MAPPER.readValue(file.toFile(), ScanResult.class);
            if (r.getFindings() == null) throw new IOException("no findings array");
            return r;
        } catch (IOException e) {
            throw new SecPipeException("could not read baseline " + file + ": " + e.getMessage(),
                    "the baseline must be the report.json written by 'secpipe scan' (not the SARIF or CSV file).");
        }
    }

    private static void print(Console c, BaselineDiff diff, Path report) {
        c.println();
        c.println(c.bold("Verification against baseline"));
        c.println("  " + c.green("fixed         " + diff.fixed().size()));
        c.println("  " + c.yellow("still present " + diff.stillPresent().size()));
        c.println("  " + c.red("new           " + diff.introduced().size()));
        section(c, "Fixed", diff.fixed());
        section(c, "Still present", diff.stillPresent());
        section(c, "New", diff.introduced());
        c.println();
        c.println("Verification report: " + report);
    }

    private static void section(Console c, String title, List<Finding> findings) {
        if (findings.isEmpty()) return;
        c.println();
        c.println(c.bold(title));
        for (Finding f : findings) {
            c.println("  " + c.severity(f.getSeverity()) + " " + label(f) + "  " + c.dim(f.location()));
        }
    }

    private static String label(Finding f) {
        String id = f.primaryCwe() != null ? f.primaryCwe() : f.getRuleId();
        if (f.getCategory() == ca.carleton.secpipe.core.Category.DEPENDENCIES) id = f.primaryVulnId();
        return id + " " + (f.getTitle() == null ? "" : f.getTitle());
    }
}
