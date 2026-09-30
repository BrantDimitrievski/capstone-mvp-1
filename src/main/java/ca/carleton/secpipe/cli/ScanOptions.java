package ca.carleton.secpipe.cli;

import ca.carleton.secpipe.core.ScanConfig;
import ca.carleton.secpipe.core.SecPipeException;
import ca.carleton.secpipe.core.Severity;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Options shared by {@code scan} and {@code verify}. */
public class ScanOptions {

    @Option(names = {"-l", "--lang"}, defaultValue = "java", paramLabel = "LANG",
            description = "Language of the codebase. Supported: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}.",
            completionCandidates = Languages.class)
    String language;

    @Option(names = {"-c", "--category"}, defaultValue = "all", paramLabel = "SCOPE",
            description = "What to analyze: code (source SAST), deps (dependency CVEs) or all. Default: ${DEFAULT-VALUE}.")
    ScanConfig.Scope scope;

    @Option(names = {"-f", "--format"}, split = ",", paramLabel = "FMT",
            description = "Report formats: md, html, json, csv, sarif (comma separated). Default: all.")
    List<String> formats;

    @Option(names = "--no-ai", description = "Disable LLM assistance; use deterministic agents only.")
    boolean noAi;

    @Option(names = "--ai-max", defaultValue = "15", paramLabel = "N",
            description = "Max findings sent to the LLM for review/test generation. Default: ${DEFAULT-VALUE}.")
    int aiMax;

    @Option(names = "--fail-on", defaultValue = "high", paramLabel = "SEVERITY",
            description = "Exit with code 1 when a finding is at or above this severity "
                    + "(critical, high, medium, low, info, none). Default: ${DEFAULT-VALUE}.")
    String failOn;

    @Option(names = "--tools", split = ",", paramLabel = "ID",
            description = "Only run these analyzers (see 'secpipe doctor' for ids).")
    List<String> tools;

    @Option(names = "--exclude-tools", split = ",", paramLabel = "ID", description = "Skip these analyzers.")
    List<String> excludeTools;

    @Option(names = "--include-tests", description = "Also analyze test sources (src/test/...).")
    boolean includeTests;

    @Option(names = "--offline", description = "Do not call online vulnerability databases (uses the local cache only).")
    boolean offline;

    @Option(names = "--no-tests", description = "Do not generate security regression tests.")
    boolean noTests;

    @Option(names = "--deps-from", defaultValue = "auto", paramLabel = "MODE",
            description = "How to resolve dependencies: auto (build tool, then manifest), build, manifest. Default: ${DEFAULT-VALUE}.")
    ScanConfig.DependencyResolution depsFrom;

    @Option(names = {"-q", "--quiet"}, description = "Only print the final summary and errors.")
    boolean quiet;

    @Option(names = {"-v", "--verbose"}, description = "Print debug output and stack traces.")
    boolean verbose;

    static class Languages extends java.util.ArrayList<String> {
        Languages() {
            super(ScanConfig.SUPPORTED_LANGUAGES);
        }
    }

    ScanConfig toConfig(Path target, Path outDir) throws SecPipeException {
        Path root = target.toAbsolutePath().normalize();
        if (!Files.exists(root)) {
            throw new SecPipeException("path does not exist: " + target,
                    "pass the folder of the project to scan, e.g. 'secpipe scan ./my-app'.");
        }
        if (!Files.isDirectory(root)) {
            throw new SecPipeException("not a directory: " + target,
                    "secpipe scans a project folder, not a single file. Pass the project root.");
        }
        String lang = language.toLowerCase(Locale.ROOT).trim();
        if (!ScanConfig.SUPPORTED_LANGUAGES.contains(lang)) {
            throw new SecPipeException("language '" + language + "' is not supported yet.",
                    "supported languages: " + String.join(", ", ScanConfig.SUPPORTED_LANGUAGES) + ".");
        }
        Set<String> fmt = new LinkedHashSet<>();
        if (formats == null || formats.isEmpty()) {
            fmt.addAll(List.of("md", "html", "json", "csv", "sarif"));
        } else {
            for (String f : formats) {
                String v = f.toLowerCase(Locale.ROOT).trim();
                if (v.equals("markdown")) v = "md";
                if (!ScanConfig.ALL_FORMATS.contains(v)) {
                    throw new SecPipeException("unknown report format '" + f + "'.",
                            "use one or more of: md, html, json, csv, sarif.");
                }
                fmt.add(v);
            }
        }
        return new ScanConfig()
                .setTarget(root)
                .setLanguage(lang)
                .setScope(scope)
                .setFormats(fmt)
                .setOutDir(outDir.toAbsolutePath().normalize())
                .setAiEnabled(!noAi)
                .setAiMaxFindings(Math.max(0, aiMax))
                .setFailOn(parseFailOn(failOn))
                .setOnlyTools(normalize(tools))
                .setExcludeTools(normalize(excludeTools))
                .setIncludeTests(includeTests)
                .setOffline(offline)
                .setGenerateTests(!noTests)
                .setDependencyResolution(depsFrom);
    }

    static Severity parseFailOn(String raw) throws SecPipeException {
        String v = raw.toLowerCase(Locale.ROOT).trim();
        if (v.equals("none") || v.equals("never")) return null;
        for (Severity s : Severity.values()) {
            if (s.name().equalsIgnoreCase(v)) return s;
        }
        throw new SecPipeException("invalid --fail-on value '" + raw + "'.",
                "use one of: critical, high, medium, low, info, none.");
    }

    private static Set<String> normalize(List<String> values) {
        Set<String> out = new LinkedHashSet<>();
        if (values != null) values.forEach(v -> out.add(v.toLowerCase(Locale.ROOT).trim()));
        return out;
    }
}
