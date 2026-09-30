package ca.carleton.secpipe.cli;

import ca.carleton.secpipe.core.SecPipeException;
import ca.carleton.secpipe.util.Console;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Command(
        name = "secpipe",
        mixinStandardHelpOptions = true,
        versionProvider = SecPipeCli.VersionProvider.class,
        description = {
                "Defensive security analysis pipeline for Java codebases.",
                "Scans source code and dependencies, maps findings to CWE/CVE/OWASP Top 10,",
                "ranks them, generates security regression tests and writes a unified report."
        },
        subcommands = {ScanCommand.class, VerifyCommand.class, DoctorCommand.class, CommandLine.HelpCommand.class},
        footer = {"", "Quick start:  secpipe doctor && secpipe scan path/to/project"})
public class SecPipeCli implements Runnable {

    public static final int EXIT_OK = 0;
    public static final int EXIT_FINDINGS = 1;
    public static final int EXIT_ERROR = 2;

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    @Override
    public void run() {
        spec.commandLine().usage(System.out);
    }

    public static void main(String[] args) {
        System.exit(execute(args));
    }

    public static int execute(String... args) {
        return commandLine().execute(args);
    }

    public static CommandLine commandLine() {
        CommandLine cmd = new CommandLine(new SecPipeCli());
        cmd.setCaseInsensitiveEnumValuesAllowed(true);
        cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            Console console = Console.system(false, false);
            if (ex instanceof SecPipeException spe) {
                console.error(spe.getMessage());
                if (spe.hint() != null) console.hint(spe.hint());
            } else {
                console.error("unexpected failure: " + ex);
                boolean verbose = parseResult.hasMatchedOption("--verbose");
                if (verbose) {
                    ex.printStackTrace();
                } else {
                    console.hint("re-run with --verbose to see the stack trace, and please report it.");
                }
            }
            return EXIT_ERROR;
        });
        return cmd;
    }

    public static String version() {
        try (InputStream in = SecPipeCli.class.getResourceAsStream("/secpipe-version.properties")) {
            if (in == null) return "dev";
            Properties p = new Properties();
            p.load(in);
            String v = p.getProperty("version", "dev");
            return v.startsWith("${") ? "dev" : v;
        } catch (IOException e) {
            return "dev";
        }
    }

    public static class VersionProvider implements CommandLine.IVersionProvider {
        @Override
        public String[] getVersion() {
            return new String[]{"secpipe " + version() + " (Java " + Runtime.version() + ")"};
        }
    }
}
