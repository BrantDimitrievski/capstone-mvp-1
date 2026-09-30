package ca.carleton.secpipe.cli;

import ca.carleton.secpipe.agents.ProjectDetector;
import ca.carleton.secpipe.core.BuildTool;
import ca.carleton.secpipe.llm.LlmSettings;
import ca.carleton.secpipe.tools.OsvClient;
import ca.carleton.secpipe.tools.ScannerAdapter;
import ca.carleton.secpipe.tools.ToolRegistry;
import ca.carleton.secpipe.util.Console;
import ca.carleton.secpipe.util.Proc;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.Callable;

@Command(name = "doctor", mixinStandardHelpOptions = true,
        description = {
                "Check the environment: JDK, build tools, optional analyzers, network and LLM settings.",
                "Pass a project path to also check that project's build setup."
        })
public class DoctorCommand implements Callable<Integer> {

    @Parameters(index = "0", arity = "0..1", paramLabel = "PATH", description = "Optional project to check.")
    Path project;

    private Console c;
    private int failures;

    @Override
    public Integer call() {
        c = Console.system(false, false);
        c.println(c.bold("secpipe " + SecPipeCli.version() + " environment check"));
        c.println();

        c.println(c.bold("Java"));
        Runtime.Version v = Runtime.version();
        String javaHome = System.getProperty("java.home");
        if (v.feature() >= 21) {
            ok("Java " + v + " (" + System.getProperty("java.vendor") + ") at " + javaHome);
        } else {
            fail("Java " + v + " is too old; secpipe needs Java 21+", "install JDK 21+ (https://adoptium.net) and set JAVA_HOME.");
        }
        String envHome = System.getenv("JAVA_HOME");
        if (envHome == null || envHome.isBlank()) {
            warn("JAVA_HOME is not set", "some build tools (Maven wrapper, Gradle) need it. Point it at your JDK folder.");
        } else if (!Files.isDirectory(Path.of(envHome))) {
            fail("JAVA_HOME points to a missing folder: " + envHome, "fix JAVA_HOME so that $JAVA_HOME/bin/java exists.");
        } else {
            ok("JAVA_HOME=" + envHome);
        }
        Optional<Path> javac = Proc.which("javac");
        if (javac.isPresent()) ok("javac found at " + javac.get() + " (needed to compile generated tests)");
        else warn("javac not found on PATH (a JRE is installed, not a full JDK)",
                "install a JDK if you want to compile and run the generated regression tests.");

        c.println();
        c.println(c.bold("Build tools"));
        tool("mvn", "-v", "Maven", "optional: install Maven or use the project's ./mvnw wrapper.");
        tool("gradle", "--version", "Gradle", "optional: only needed for Gradle projects without ./gradlew.");

        if (project != null) checkProject(project.toAbsolutePath().normalize());

        c.println();
        c.println(c.bold("Analyzers"));
        for (ScannerAdapter a : ToolRegistry.defaults().all()) {
            String label = String.format("%-9s %-34s [%s]", a.id(), a.displayName(), a.category().name().toLowerCase());
            if (a.isAvailable()) ok(label + " " + c.dim(a.detail()));
            else info(label + " " + c.dim("skipped: " + a.unavailableReason()));
        }

        c.println();
        c.println(c.bold("Network"));
        if (OsvClient.reachable()) ok("OSV.dev vulnerability database reachable (" + OsvClient.baseUrl() + ")");
        else warn("cannot reach " + OsvClient.baseUrl(),
                "dependency CVE lookup needs internet; use --offline to rely on the local cache in ~/.secpipe/cache.");

        c.println();
        c.println(c.bold("AI assistance"));
        LlmSettings llm = LlmSettings.fromEnvironment();
        if (llm.configured()) {
            ok("LLM configured: model " + llm.model() + " at " + llm.baseUrl()
                    + (llm.apiKey() == null ? " (no API key, e.g. local Ollama)" : ""));
        } else {
            info("no LLM configured; agents use deterministic heuristics. "
                    + c.dim("Set SECPIPE_LLM_KEY (OpenAI) or SECPIPE_LLM_URL (e.g. Ollama) to enable."));
        }

        c.println();
        if (failures == 0) {
            c.println(c.green("Ready. Run: secpipe scan " + (project == null ? "<path-to-project>" : project)));
            return SecPipeCli.EXIT_OK;
        }
        c.println(c.red(failures + " problem(s) must be fixed before scanning."));
        return SecPipeCli.EXIT_ERROR;
    }

    private void checkProject(Path root) {
        c.println();
        c.println(c.bold("Project " + root));
        if (!Files.isDirectory(root)) {
            fail("not a directory", "pass the root folder of the project you want to scan.");
            return;
        }
        BuildTool bt = ProjectDetector.detectBuildTool(root);
        if (bt == BuildTool.NONE) {
            warn("no pom.xml or build.gradle found", "source scanning still works; dependency scanning needs a manifest.");
        } else {
            ok("build tool: " + bt.label());
        }
        if (bt == BuildTool.MAVEN_WRAPPER) checkWrapper(root.resolve("mvnw"));
        if (bt == BuildTool.GRADLE_WRAPPER) checkWrapper(root.resolve("gradlew"));
        if (bt != BuildTool.NONE && ProjectDetector.buildCommand(root, bt) == null) {
            warn("no runnable " + bt.label() + " found",
                    "secpipe will parse the manifest directly (--deps-from manifest); transitive dependencies will be missed.");
        }
        try {
            int n = ProjectDetector.findSources(root, ".java", false).size();
            if (n == 0) warn("no .java source files found", "check the path; test sources are skipped unless --include-tests.");
            else ok(n + " Java source file(s) to analyze");
        } catch (Exception e) {
            fail("cannot read project: " + e.getMessage(), "check file permissions.");
        }
    }

    private void checkWrapper(Path wrapper) {
        if (!Proc.isWindows() && Files.isRegularFile(wrapper) && !Files.isExecutable(wrapper)) {
            warn(wrapper.getFileName() + " is not executable", "run: chmod +x " + wrapper);
        } else if (Files.isRegularFile(wrapper)) {
            ok("wrapper present: " + wrapper.getFileName());
        }
    }

    private void tool(String exe, String flag, String name, String hint) {
        Optional<Path> p = Proc.which(exe);
        if (p.isPresent()) {
            ok(name + ": " + Proc.version(p.get(), flag).orElse(p.get().toString()));
        } else {
            info(name + " not on PATH " + c.dim("(" + hint + ")"));
        }
    }

    private void ok(String msg) {
        c.println("  " + c.green("[ ok ]") + " " + msg);
    }

    private void info(String msg) {
        c.println("  " + c.dim("[info]") + " " + msg);
    }

    private void warn(String msg, String hint) {
        c.println("  " + c.yellow("[warn]") + " " + msg);
        c.println("         " + c.dim(hint));
    }

    private void fail(String msg, String hint) {
        failures++;
        c.println("  " + c.red("[fail]") + " " + msg);
        c.println("         " + c.dim(hint));
    }
}
