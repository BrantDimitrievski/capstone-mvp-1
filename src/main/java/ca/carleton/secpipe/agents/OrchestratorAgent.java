package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.cli.SecPipeCli;
import ca.carleton.secpipe.core.BuildTool;
import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.CodeMap;
import ca.carleton.secpipe.core.ProjectProfile;
import ca.carleton.secpipe.core.ScanConfig;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.SecPipeException;
import ca.carleton.secpipe.core.ToolRun;
import ca.carleton.secpipe.knowledge.KnowledgeBase;
import ca.carleton.secpipe.llm.LlmClient;
import ca.carleton.secpipe.llm.LlmClients;
import ca.carleton.secpipe.tools.OsvAdapter;
import ca.carleton.secpipe.tools.ScannerAdapter;
import ca.carleton.secpipe.tools.ToolRegistry;
import ca.carleton.secpipe.tools.deps.DependencyResolver;
import ca.carleton.secpipe.util.Console;
import ca.carleton.secpipe.util.SourceText;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;

import java.io.IOException;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Entry point of the pipeline. Profiles the codebase, turns it into an analyzable form (parsed ASTs
 * and a code map), plans which analyzers run, then coordinates the specialized agents.
 */
public class OrchestratorAgent implements Agent {

    public record Outcome(ScanResult result, List<Path> reports) {
    }

    private final ToolRegistry registry;
    private final Console console;
    private List<ToolRegistry.Selection> plan = List.of();

    public OrchestratorAgent(ToolRegistry registry, Console console) {
        this.registry = registry;
        this.console = console;
    }

    @Override
    public String name() {
        return "orchestrator";
    }

    @Override
    public String role() {
        return "Profiles the project, builds the code map, plans the scan and coordinates the other agents.";
    }

    public Outcome execute(ScanConfig config) throws SecPipeException {
        long start = System.nanoTime();
        String startedAt = OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        PipelineState state = new PipelineState();

        console.step("Profiling " + config.getTarget());
        long t = System.nanoTime();
        ProjectProfile profile = profile(config);
        state.timings().put("profile", ms(t));

        t = System.nanoTime();
        Map<Path, CompilationUnit> parsed = parse(profile.sourceFiles());
        CodeMap codeMap = CodeMapBuilder.build(parsed, profile::relativize);
        profile = new ProjectProfile(profile.root(), profile.language(), profile.buildTool(),
                CodeMapBuilder.frameworks(parsed), profile.sourceFiles(), profile.manifests(), profile.linesOfCode());
        state.timings().put("parse-and-map", ms(t));
        console.info(String.format("%s | build: %s | %d source files, %,d lines | %d classes, %d methods, %d HTTP endpoints",
                profile.language(), profile.buildTool().label(), profile.sourceFiles().size(), profile.linesOfCode(),
                codeMap.classCount(), codeMap.methodCount(), codeMap.endpoints().size()));
        if (!profile.frameworks().isEmpty()) console.info("frameworks: " + String.join(", ", profile.frameworks()));

        LlmClient llm = LlmClients.create(config.isAiEnabled(), console);
        ScanContext ctx = new ScanContext(config, profile, codeMap, parsed, KnowledgeBase.load(), llm, console);

        run(ctx, state);

        ScanResult result = buildResult(ctx, state, startedAt);
        result.setDurationMs(ms(start));
        state.timings().put("total", result.getDurationMs());
        result.setStageTimingsMs(state.timings());

        t = System.nanoTime();
        new ReportAgent(result).run(ctx, state);
        state.timings().put("report", ms(t));
        result.setStageTimingsMs(state.timings());
        return new Outcome(result, List.copyOf(state.reports()));
    }

    /** Runs the analysis agents on an already-built context. */
    @Override
    public void run(ScanContext ctx, PipelineState state) throws SecPipeException {
        plan = registry.plan(ctx.profile(), ctx.config());
        List<ScannerAdapter> selected = plan.stream().filter(ToolRegistry.Selection::selected).map(ToolRegistry.Selection::adapter).toList();
        plan.stream().filter(s -> !s.selected()).forEach(s -> state.toolRuns().add(s.asSkipped()));
        console.step("Plan: " + (selected.isEmpty() ? "no analyzers available" : String.join(", ", selected.stream().map(ScannerAdapter::id).toList()))
                + (ctx.llm().enabled() ? " | AI: " + ctx.llm().model() : " | AI: off"));
        plan.stream().filter(s -> !s.selected() && ctx.config().getScope().categories().contains(s.adapter().category()))
                .forEach(s -> console.info("skipping " + s.adapter().id() + ": " + s.reason()));
        if (selected.isEmpty()) {
            throw new SecPipeException("no analyzer can run for this project and configuration.",
                    "check --category/--tools, or run 'secpipe doctor " + ctx.root() + "'.");
        }

        console.step("Analyzing code and dependencies");
        CodePatternAgent code = new CodePatternAgent(selected);
        DependencyAgent deps = new DependencyAgent(selected);
        CompletableFuture<Long> codeRun = CompletableFuture.supplyAsync(() -> timed(() -> code.run(ctx, state)), AdapterRunner.POOL);
        CompletableFuture<Long> depsRun = CompletableFuture.supplyAsync(() -> timed(() -> deps.run(ctx, state)), AdapterRunner.POOL);
        try {
            state.timings().put("code-analysis", codeRun.join());
            state.timings().put("dependency-analysis", depsRun.join());
        } catch (CompletionException e) {
            throw new SecPipeException("analysis failed: " + e.getCause().getMessage(), "re-run with --verbose for details.", e);
        }

        console.step("Enriching, validating and ranking " + state.findings().size() + " raw finding(s)");
        List<Agent> agents = List.of(new KnowledgeAgent(), new ExploitabilityAgent(), new TriageAgent());
        for (Agent agent : agents) {
            long t = System.nanoTime();
            agent.run(ctx, state);
            state.timings().put(agent.name(), ms(t));
        }

        if (ctx.config().isGenerateTests()) {
            console.step("Generating security regression tests");
            long t = System.nanoTime();
            new TestGenAgent().run(ctx, state);
            state.timings().put("test-generation", ms(t));
        }
    }

    private ProjectProfile profile(ScanConfig config) throws SecPipeException {
        Path root = config.getTarget();
        BuildTool buildTool = ProjectDetector.detectBuildTool(root);
        List<Path> sources;
        List<Path> manifests;
        try {
            sources = ProjectDetector.findSources(root, ".java", config.isIncludeTests());
            manifests = ProjectDetector.findManifests(root);
        } catch (IOException e) {
            throw new SecPipeException("cannot read " + root + ": " + e.getMessage(), "check that the folder exists and is readable.");
        }
        Set<Category> scope = config.getScope().categories();
        if (sources.isEmpty() && manifests.isEmpty()) {
            throw new SecPipeException("no Java source files or build manifests (pom.xml, build.gradle) found under " + root + ".",
                    "make sure PATH points at a Java project root. Test sources are skipped unless --include-tests is set.");
        }
        if (scope.equals(Set.of(Category.CODE)) && sources.isEmpty()) {
            throw new SecPipeException("no Java source files found under " + root + " (--category code).",
                    "point secpipe at the project root, or use --include-tests if the project only has test sources.");
        }
        if (scope.equals(Set.of(Category.DEPENDENCIES)) && manifests.isEmpty()) {
            throw new SecPipeException("no pom.xml or build.gradle found under " + root + " (--category deps).",
                    "dependency scanning needs a Maven or Gradle manifest.");
        }
        if (scope.contains(Category.CODE) && sources.isEmpty()) console.warn("no Java source files found; only dependencies will be scanned.");
        if (scope.contains(Category.DEPENDENCIES) && manifests.isEmpty()) {
            console.warn("no pom.xml or build.gradle found; dependency scanning is skipped.");
        }
        long loc = sources.parallelStream().mapToLong(p -> SourceText.readLines(p).size()).sum();
        return new ProjectProfile(root, config.getLanguage(), buildTool, Set.of(), sources, manifests, loc);
    }

    private Map<Path, CompilationUnit> parse(List<Path> files) {
        Map<Path, CompilationUnit> out = new ConcurrentHashMap<>();
        AtomicInteger failed = new AtomicInteger();
        ThreadLocal<JavaParser> parsers = ThreadLocal.withInitial(() -> new JavaParser(
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)));
        files.parallelStream().forEach(p -> {
            try {
                ParseResult<CompilationUnit> r = parsers.get().parse(p);
                if (r.getResult().isPresent()) out.put(p, r.getResult().get());
                else failed.incrementAndGet();
                if (!r.isSuccessful()) console.debug("parse problems in " + p + ": " + r.getProblems().size());
            } catch (IOException | RuntimeException | StackOverflowError e) {
                failed.incrementAndGet();
                console.debug("could not parse " + p + ": " + e);
            }
        });
        if (failed.get() > 0) {
            console.warn(failed.get() + " file(s) could not be parsed and were skipped by the built-in rules (use --verbose for details).");
        }
        return out;
    }

    private ScanResult buildResult(ScanContext ctx, PipelineState state, String startedAt) {
        ProjectProfile p = ctx.profile();
        DependencyResolver.Resolution deps = ctx.get(OsvAdapter.DEPENDENCIES_KEY);
        ScanResult r = new ScanResult();
        r.setVersion(SecPipeCli.version());
        r.setStartedAt(startedAt);
        r.setProject(new ScanResult.ProjectSummary(
                p.root().getFileName() == null ? p.root().toString() : p.root().getFileName().toString(),
                p.root().toString(), p.language(), p.buildTool().label(), new ArrayList<>(p.frameworks()),
                p.sourceFiles().size(), p.linesOfCode(), ctx.codeMap().classCount(), ctx.codeMap().methodCount(),
                ctx.codeMap().endpoints().size(), deps == null ? 0 : deps.dependencies().size()));
        List<String> ran = state.toolRuns().stream().filter(tr -> tr.status() != ToolRun.Status.SKIPPED).map(ToolRun::tool).toList();
        r.setSettings(new ScanResult.ScanSettings(ctx.config().getScope().name().toLowerCase(), ctx.llm().enabled(),
                ctx.llm().enabled() ? ctx.llm().model() : null, ran, ctx.config().isIncludeTests()));
        List<ToolRun> runs = new ArrayList<>(state.toolRuns());
        List<String> order = registry.all().stream().map(ScannerAdapter::id).toList();
        runs.sort((a, b) -> Integer.compare(order.indexOf(a.tool()), order.indexOf(b.tool())));
        r.setToolRuns(runs);
        r.setFindings(state.findings());
        r.setGeneratedTests(state.generatedTests());
        return r;
    }

    private static long timed(Runnable r) {
        long t = System.nanoTime();
        r.run();
        return ms(t);
    }

    private static long ms(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }
}
