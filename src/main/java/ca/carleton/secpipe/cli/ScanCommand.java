package ca.carleton.secpipe.cli;

import ca.carleton.secpipe.agents.OrchestratorAgent;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanConfig;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.report.TerminalSummary;
import ca.carleton.secpipe.tools.ToolRegistry;
import ca.carleton.secpipe.util.Console;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "scan", mixinStandardHelpOptions = true,
        description = {
                "Scan a project and write a unified security report.",
                "Exit codes: 0 = no findings at/above --fail-on, 1 = findings at/above --fail-on, 2 = error."
        })
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", defaultValue = ".", paramLabel = "PATH",
            description = "Project root to scan. Default: current directory.")
    Path target;

    @Option(names = {"-o", "--out"}, defaultValue = "secpipe-out", paramLabel = "DIR",
            description = "Output directory for reports and generated tests. Default: ${DEFAULT-VALUE}.")
    Path out;

    @Option(names = "--top", defaultValue = "10", paramLabel = "N",
            description = "How many findings to list in the terminal summary. Default: ${DEFAULT-VALUE}.")
    int top;

    @Mixin
    ScanOptions options;

    @Override
    public Integer call() throws Exception {
        ScanConfig config = options.toConfig(target, out);
        Console console = Console.system(options.quiet, options.verbose);
        OrchestratorAgent.Outcome outcome = new OrchestratorAgent(ToolRegistry.defaults(), console).execute(config);
        new TerminalSummary(console).print(outcome.result(), outcome.reports(), top, config.getFailOn());
        return exitCode(outcome.result().getFindings(), config.getFailOn());
    }

    static int exitCode(List<Finding> findings, Severity failOn) {
        if (failOn == null) return SecPipeCli.EXIT_OK;
        boolean fail = findings.stream().anyMatch(f -> f.getSeverity().atLeast(failOn));
        return fail ? SecPipeCli.EXIT_FINDINGS : SecPipeCli.EXIT_OK;
    }

    static int exitCode(ScanResult result, Severity failOn) {
        return exitCode(result.getFindings(), failOn);
    }
}
