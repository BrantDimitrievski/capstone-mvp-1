package ca.carleton.secpipe.core;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Everything the user chose for one scan (FR1: scope selection). */
public class ScanConfig {

    public enum Scope {
        CODE, DEPS, ALL;

        public Set<Category> categories() {
            return switch (this) {
                case CODE -> EnumSet.of(Category.CODE);
                case DEPS -> EnumSet.of(Category.DEPENDENCIES);
                case ALL -> EnumSet.allOf(Category.class);
            };
        }
    }

    public enum DependencyResolution { AUTO, BUILD, MANIFEST }

    public static final List<String> SUPPORTED_LANGUAGES = List.of("java");
    public static final Set<String> ALL_FORMATS = Set.of("md", "html", "json", "csv", "sarif");

    private Path target;
    private String language = "java";
    private Scope scope = Scope.ALL;
    private Set<String> formats = new LinkedHashSet<>(List.of("md", "html", "json", "csv", "sarif"));
    private Path outDir;
    private boolean aiEnabled = true;
    private int aiMaxFindings = 15;
    private Severity failOn = Severity.HIGH;
    private Set<String> onlyTools = new LinkedHashSet<>();
    private Set<String> excludeTools = new LinkedHashSet<>();
    private boolean includeTests;
    private boolean offline;
    private boolean generateTests = true;
    private DependencyResolution dependencyResolution = DependencyResolution.AUTO;

    public Path getTarget() { return target; }
    public ScanConfig setTarget(Path target) { this.target = target; return this; }
    public String getLanguage() { return language; }
    public ScanConfig setLanguage(String language) { this.language = language; return this; }
    public Scope getScope() { return scope; }
    public ScanConfig setScope(Scope scope) { this.scope = scope; return this; }
    public Set<String> getFormats() { return formats; }
    public ScanConfig setFormats(Set<String> formats) { this.formats = new LinkedHashSet<>(formats); return this; }
    public Path getOutDir() { return outDir; }
    public ScanConfig setOutDir(Path outDir) { this.outDir = outDir; return this; }
    public boolean isAiEnabled() { return aiEnabled; }
    public ScanConfig setAiEnabled(boolean aiEnabled) { this.aiEnabled = aiEnabled; return this; }
    public int getAiMaxFindings() { return aiMaxFindings; }
    public ScanConfig setAiMaxFindings(int aiMaxFindings) { this.aiMaxFindings = aiMaxFindings; return this; }
    /** Null means "never fail". */
    public Severity getFailOn() { return failOn; }
    public ScanConfig setFailOn(Severity failOn) { this.failOn = failOn; return this; }
    public Set<String> getOnlyTools() { return onlyTools; }
    public ScanConfig setOnlyTools(Set<String> onlyTools) { this.onlyTools = new LinkedHashSet<>(onlyTools); return this; }
    public Set<String> getExcludeTools() { return excludeTools; }
    public ScanConfig setExcludeTools(Set<String> excludeTools) { this.excludeTools = new LinkedHashSet<>(excludeTools); return this; }
    public boolean isIncludeTests() { return includeTests; }
    public ScanConfig setIncludeTests(boolean includeTests) { this.includeTests = includeTests; return this; }
    public boolean isOffline() { return offline; }
    public ScanConfig setOffline(boolean offline) { this.offline = offline; return this; }
    public boolean isGenerateTests() { return generateTests; }
    public ScanConfig setGenerateTests(boolean generateTests) { this.generateTests = generateTests; return this; }
    public DependencyResolution getDependencyResolution() { return dependencyResolution; }
    public ScanConfig setDependencyResolution(DependencyResolution r) { this.dependencyResolution = r; return this; }
}
