package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.cli.SecPipeCli;
import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.CodeMap;
import ca.carleton.secpipe.core.DependencyRef;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.SecPipeException;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.llm.LlmClient;
import ca.carleton.secpipe.tools.deps.VersionComparator;
import ca.carleton.secpipe.util.Json;
import ca.carleton.secpipe.util.SourceText;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Generates JUnit 5 security regression tests (FR4/FR5). Every code finding gets a source guard that
 * fails while the flagged code (or the same vulnerable pattern) is present, plus a payload-driven
 * behavioural test skeleton. Dependency findings get a classpath version check. With an LLM configured,
 * the top findings also get a fully wired behavioural test drafted by the model.
 */
public class TestGenAgent implements Agent {

    public static final String PACKAGE = "secpipe.generated";
    static final String DIR = "generated-tests";

    record Template(String label, String vulnerable, String mitigation, List<String> payloads, String behaviour, String assertion) {
    }

    private static final String LLM_SYSTEM = """
            You write focused JUnit 5 security regression tests for Java code. Output only one complete Java
            source file in a ```java code block. No explanations.""";

    private final Map<String, Template> templates = loadTemplates();

    @Override
    public String name() {
        return "test-generation";
    }

    @Override
    public String role() {
        return "Generates JUnit 5 security regression tests that fail while a vulnerability is present.";
    }

    @Override
    public void run(ScanContext ctx, PipelineState state) throws SecPipeException {
        List<Finding> findings;
        synchronized (state.findings()) {
            findings = List.copyOf(state.findings());
        }
        if (findings.isEmpty()) return;
        Path base = ctx.config().getOutDir().resolve(DIR);
        Path pkgDir = base.resolve("src/test/java").resolve(PACKAGE.replace('.', '/'));
        try {
            if (Files.isDirectory(pkgDir)) {
                try (var files = Files.list(pkgDir)) {
                    for (Path p : files.toList()) {
                        if (p.toString().endsWith(".java")) Files.delete(p);
                    }
                }
            }
            Files.createDirectories(pkgDir);
            write(pkgDir.resolve("SecurityTestSupport.java"), supportClass());
            Set<String> names = new LinkedHashSet<>();
            List<Finding> codeFindings = new ArrayList<>();
            for (Finding f : findings) {
                if (f.getCategory() != Category.CODE || f.getLine() <= 0) continue;
                String className = uniqueName(names, className(f));
                write(pkgDir.resolve(className + ".java"), codeTest(ctx, f, className));
                f.setGeneratedTest(DIR + "/src/test/java/" + PACKAGE.replace('.', '/') + "/" + className + ".java");
                state.generatedTests().add(f.getGeneratedTest());
                codeFindings.add(f);
            }
            List<Finding> deps = findings.stream()
                    .filter(f -> f.getCategory() == Category.DEPENDENCIES && f.getDependency() != null
                            && f.getDependency().fixedVersion() != null)
                    .toList();
            if (!deps.isEmpty()) {
                String rel = DIR + "/src/test/java/" + PACKAGE.replace('.', '/') + "/DependencyVersionsSecurityTest.java";
                write(pkgDir.resolve("DependencyVersionsSecurityTest.java"), dependencyTest(deps));
                deps.forEach(f -> f.setGeneratedTest(rel));
                state.generatedTests().add(rel);
            }
            write(base.resolve("README.md"), readme(ctx));
            if (ctx.llm().enabled() && ctx.config().getAiMaxFindings() > 0) {
                llmTests(ctx, state, codeFindings, pkgDir);
            }
        } catch (IOException e) {
            throw new SecPipeException("could not write generated tests to " + pkgDir + ": " + e.getMessage(),
                    "check that the --out directory is writable, or pass --no-tests.");
        }
        ctx.console().info(state.generatedTests().size() + " test file(s) written to " + base);
    }

    // ---- code findings -------------------------------------------------------------------------

    String codeTest(ScanContext ctx, Finding f, String className) {
        String cwe = f.primaryCwe() == null ? "" : f.primaryCwe();
        Template t = templates.get(cwe);
        Optional<CodeMap.MethodInfo> method = ctx == null ? Optional.empty() : ctx.codeMap().methodAt(f.getFile(), f.getLine());
        String label = t != null ? t.label() : (f.getTitle() == null ? f.getRuleId() : f.getTitle());
        StringBuilder sb = new StringBuilder();
        sb.append("package ").append(PACKAGE).append(";\n\n");
        sb.append("import org.junit.jupiter.api.Disabled;\n");
        sb.append("import org.junit.jupiter.api.DisplayName;\n");
        sb.append("import org.junit.jupiter.api.Test;\n");
        if (t != null && t.payloads() != null) {
            sb.append("import org.junit.jupiter.params.ParameterizedTest;\n");
            sb.append("import org.junit.jupiter.params.provider.ValueSource;\n");
        }
        sb.append("\nimport java.util.regex.Pattern;\n\n");
        sb.append("import static org.junit.jupiter.api.Assertions.assertFalse;\n");
        sb.append("import static org.junit.jupiter.api.Assertions.assertTrue;\n");
        sb.append("import static org.junit.jupiter.api.Assertions.fail;\n\n");
        sb.append("/**\n");
        sb.append(" * Security regression test for secpipe finding ").append(f.getId()).append(": ").append(javadoc(f.getTitle())).append("\n");
        sb.append(" * <p>\n");
        sb.append(" * ").append(javadoc(String.join(", ", f.getCwes()))).append(f.getOwasp() == null ? "" : " / OWASP " + javadoc(f.getOwasp()))
                .append(" at ").append(javadoc(f.location())).append(method.map(m -> " in " + m.qualifiedName() + "()").orElse("")).append(".\n");
        sb.append(" * These tests fail while the vulnerability is present and keep it from coming back after a fix.\n");
        sb.append(" * Generated by secpipe ").append(SecPipeCli.version()).append(".\n");
        sb.append(" */\n");
        sb.append("@DisplayName(\"").append(esc(f.getId() + " " + cwe + " " + label + " in " + fileName(f.getFile()) + ":" + f.getLine())).append("\")\n");
        sb.append("class ").append(className).append(" {\n\n");
        sb.append("    private static final String FILE = \"").append(esc(f.getFile())).append("\";\n");
        sb.append("    private static final String FLAGGED = \"").append(esc(f.getSnippet() == null ? "" : f.getSnippet())).append("\";\n");
        if (t != null) {
            sb.append("    private static final Pattern VULNERABLE = Pattern.compile(\"").append(esc(t.vulnerable())).append("\");\n");
            sb.append("    private static final Pattern MITIGATION = ")
                    .append(t.mitigation() == null ? "null" : "Pattern.compile(\"" + esc(t.mitigation()) + "\")").append(";\n");
        }
        sb.append("\n");
        sb.append("    @Test\n");
        sb.append("    @DisplayName(\"flagged statement has been remediated\")\n");
        sb.append("    void flaggedStatementIsGone() {\n");
        sb.append("        String source = SecurityTestSupport.source(FILE);\n");
        sb.append("        assertFalse(!FLAGGED.isEmpty() && SecurityTestSupport.normalize(source).contains(SecurityTestSupport.normalize(FLAGGED)),\n");
        sb.append("                \"").append(esc(label)).append(" still present in \" + FILE + \": \" + FLAGGED);\n");
        sb.append("    }\n");
        if (t != null) {
            sb.append("\n");
            sb.append("    @Test\n");
            sb.append("    @DisplayName(\"").append(esc(label)).append(" pattern does not reappear in this file\")\n");
            sb.append("    void vulnerablePatternDoesNotReappear() {\n");
            sb.append("        String source = SecurityTestSupport.source(FILE);\n");
            sb.append("        boolean vulnerable = VULNERABLE.matcher(source).find();\n");
            sb.append("        boolean mitigated = MITIGATION != null && MITIGATION.matcher(source).find();\n");
            sb.append("        assertTrue(!vulnerable || mitigated, \"").append(esc(label))
                    .append(" pattern found in \" + FILE + \" without a recognised mitigation\");\n");
            sb.append("    }\n");
            sb.append("\n");
            String target = method.map(m -> m.qualifiedName() + "() (lines " + m.beginLine() + "-" + m.endLine() + ")").orElse("the vulnerable method");
            sb.append("    /**\n");
            sb.append("     * Behavioural check. Target: ").append(javadoc(target)).append(".\n");
            sb.append("     * ").append(javadoc(t.behaviour())).append("\n");
            sb.append("     */\n");
            sb.append("    @Disabled(\"Wire up ").append(esc(target)).append(" with test fixtures, then remove @Disabled\")\n");
            if (t.payloads() != null) {
                sb.append("    @ParameterizedTest(name = \"rejects payload {0}\")\n");
                sb.append("    @ValueSource(strings = {\n");
                for (int i = 0; i < t.payloads().size(); i++) {
                    sb.append("            \"").append(esc(t.payloads().get(i))).append("\"").append(i < t.payloads().size() - 1 ? ",\n" : "\n");
                }
                sb.append("    })\n");
                sb.append("    void rejectsAttackPayloads(String payload) {\n");
            } else {
                sb.append("    @Test\n");
                sb.append("    void behaviourIsSecure() {\n");
            }
            sb.append("        // Example:\n");
            method.ifPresent(m -> sb.append("        // ").append(m.className()).append(" target = new ").append(m.className()).append("(/* test dependencies */);\n"));
            if (t.assertion() != null) sb.append("        // ").append(t.assertion()).append("\n");
            sb.append("        fail(\"Behavioural test not wired yet\");\n");
            sb.append("    }\n");
        }
        sb.append("}\n");
        return sb.toString();
    }

    // ---- dependency findings -------------------------------------------------------------------

    String dependencyTest(List<Finding> deps) {
        Map<String, String[]> byArtifact = new LinkedHashMap<>();
        for (Finding f : deps) {
            DependencyRef d = f.getDependency();
            String key = d.group() + ":" + d.artifact();
            String[] cur = byArtifact.get(key);
            String advisory = f.primaryVulnId();
            if (cur == null) {
                byArtifact.put(key, new String[]{d.group(), d.artifact(), d.fixedVersion(), advisory});
            } else {
                if (VersionComparator.INSTANCE.compare(d.fixedVersion(), cur[2]) > 0) cur[2] = d.fixedVersion();
                if (!cur[3].contains(advisory)) cur[3] = cur[3] + " " + advisory;
            }
        }
        StringBuilder rows = new StringBuilder();
        List<String[]> list = new ArrayList<>(byArtifact.values());
        for (int i = 0; i < list.size(); i++) {
            String[] r = list.get(i);
            rows.append("            \"").append(esc(r[0])).append(", ").append(esc(r[1])).append(", ").append(esc(r[2]))
                    .append(", ").append(esc(r[3])).append("\"").append(i < list.size() - 1 ? ",\n" : "\n");
        }
        return """
                package %s;

                import org.junit.jupiter.api.Assumptions;
                import org.junit.jupiter.api.DisplayName;
                import org.junit.jupiter.params.ParameterizedTest;
                import org.junit.jupiter.params.provider.CsvSource;

                import static org.junit.jupiter.api.Assertions.assertTrue;

                /**
                 * Fails while a dependency with a known vulnerability is on the test classpath at a version below
                 * the first patched release. Generated by secpipe %s.
                 */
                @DisplayName("Dependencies are at or above their first patched version")
                class DependencyVersionsSecurityTest {

                    @ParameterizedTest(name = "{0}:{1} >= {2} ({3})")
                    @CsvSource(delimiter = ',', value = {
                %s    })
                    void dependencyIsPatched(String group, String artifact, String minimumSafeVersion, String advisories) {
                        String version = SecurityTestSupport.runtimeVersion(group, artifact);
                        Assumptions.assumeTrue(version != null, artifact + " is not on the test classpath");
                        assertTrue(SecurityTestSupport.compareVersions(version, minimumSafeVersion) >= 0,
                                group + ":" + artifact + " " + version + " is affected by " + advisories
                                        + "; upgrade to " + minimumSafeVersion + " or later");
                    }
                }
                """.formatted(PACKAGE, SecPipeCli.version(), rows);
    }

    // ---- LLM-drafted behavioural tests ---------------------------------------------------------

    private void llmTests(ScanContext ctx, PipelineState state, List<Finding> codeFindings, Path pkgDir) {
        List<Finding> top = codeFindings.stream()
                .filter(f -> f.getSeverity().atLeast(Severity.HIGH) && templates.containsKey(String.valueOf(f.primaryCwe())))
                .sorted(Comparator.comparingDouble(Finding::getScore).reversed())
                .limit(Math.min(5, ctx.config().getAiMaxFindings()))
                .toList();
        if (top.isEmpty()) return;
        ctx.console().info("drafting " + top.size() + " behavioural test(s) with " + ctx.llm().model() + "...");
        SourceText sources = new SourceText(ctx.root());
        JavaParser parser = new JavaParser(new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
        top.stream().map(f -> CompletableFuture.runAsync(() -> {
            String base = f.getGeneratedTest().substring(f.getGeneratedTest().lastIndexOf('/') + 1).replace(".java", "");
            String name = base.replace("SecurityTest", "AiSecurityTest");
            List<String> lines = sources.lines(f.getFile());
            String code = String.join("\n", lines.size() > 400 ? lines.subList(Math.max(0, f.getLine() - 60),
                    Math.min(lines.size(), f.getLine() + 60)) : lines);
            Template t = templates.get(f.primaryCwe());
            String prompt = """
                    Write a JUnit 5 test class named %s in package %s that proves the %s (%s) at line %d of %s is fixed.
                    It must call the real method with these attack payloads: %s
                    and assert secure behaviour (%s). Use plain JUnit 5 (org.junit.jupiter) and, only if needed, Mockito.
                    Import the class under test from its package. The test must FAIL on the current vulnerable code.

                    ```java
                    %s
                    ```
                    """.formatted(name, PACKAGE, t.label(), f.primaryCwe(), f.getLine(), f.getFile(),
                    t.payloads() == null ? "(choose appropriate inputs)" : String.join(" | ", t.payloads()), t.behaviour(), code);
            ctx.llm().complete(LLM_SYSTEM, prompt).map(LlmClient::stripCodeFence).ifPresent(src -> {
                if (!src.contains("class " + name) || !src.contains("@Test") && !src.contains("@ParameterizedTest")) return;
                synchronized (parser) {
                    if (!parser.parse(src).isSuccessful()) return;
                }
                try {
                    write(pkgDir.resolve(name + ".java"), src.endsWith("\n") ? src : src + "\n");
                    state.generatedTests().add(DIR + "/src/test/java/" + PACKAGE.replace('.', '/') + "/" + name + ".java");
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }, AdapterRunner.POOL)).toList().forEach(future -> {
            try {
                future.join();
            } catch (RuntimeException e) {
                ctx.console().debug("LLM test generation failed: " + e.getMessage());
            }
        });
    }

    // ---- support files -------------------------------------------------------------------------

    static String supportClass() {
        return """
                package %s;

                import java.io.IOException;
                import java.io.InputStream;
                import java.io.UncheckedIOException;
                import java.nio.charset.StandardCharsets;
                import java.nio.file.Files;
                import java.nio.file.Path;
                import java.util.Properties;

                /** Helpers for secpipe-generated security regression tests. */
                final class SecurityTestSupport {

                    private SecurityTestSupport() {
                    }

                    /**
                     * Reads a source file given relative to the scanned project root. Set -Dsecpipe.projectRoot=...
                     * if the tests do not run from that root (for example in a multi-module build).
                     */
                    static String source(String relativePath) {
                        Path start = Path.of(System.getProperty("secpipe.projectRoot", System.getProperty("user.dir"))).toAbsolutePath();
                        for (Path dir = start; dir != null; dir = dir.getParent()) {
                            Path candidate = dir.resolve(relativePath);
                            if (Files.isRegularFile(candidate)) {
                                try {
                                    return Files.readString(candidate, StandardCharsets.UTF_8);
                                } catch (IOException e) {
                                    throw new UncheckedIOException(e);
                                }
                            }
                        }
                        throw new IllegalStateException("Cannot find " + relativePath + " from " + start
                                + ". Run the tests from the project root or set -Dsecpipe.projectRoot.");
                    }

                    static String normalize(String code) {
                        return code.replaceAll("\\\\s+", "");
                    }

                    /** Version of a Maven artifact on the classpath, from META-INF/maven/.../pom.properties. */
                    static String runtimeVersion(String group, String artifact) {
                        String resource = "/META-INF/maven/" + group + "/" + artifact + "/pom.properties";
                        try (InputStream in = SecurityTestSupport.class.getResourceAsStream(resource)) {
                            if (in == null) return null;
                            Properties p = new Properties();
                            p.load(in);
                            return p.getProperty("version");
                        } catch (IOException e) {
                            return null;
                        }
                    }

                    static int compareVersions(String a, String b) {
                        String[] pa = a.split("[.\\\\-]");
                        String[] pb = b.split("[.\\\\-]");
                        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
                            String x = i < pa.length ? pa[i] : "0";
                            String y = i < pb.length ? pb[i] : "0";
                            int c;
                            if (x.matches("\\\\d+") && y.matches("\\\\d+")) {
                                c = new java.math.BigInteger(x).compareTo(new java.math.BigInteger(y));
                            } else {
                                c = x.compareToIgnoreCase(y);
                            }
                            if (c != 0) return c;
                        }
                        return 0;
                    }
                }
                """.formatted(PACKAGE);
    }

    private static String readme(ScanContext ctx) {
        return """
                # secpipe generated security regression tests

                These JUnit 5 tests were generated by `secpipe scan` for `%s`.

                * `*SecurityTest.java`: one class per code finding. The **source guard** tests fail while the
                  flagged statement, or the same vulnerable pattern, is still in the file. The **behavioural** test is
                  `@Disabled` with attack payloads ready: wire it to the real method and enable it.
                * `*AiSecurityTest.java` (only with an LLM configured): behavioural tests drafted by the model. Review
                  them before committing.
                * `DependencyVersionsSecurityTest.java`: fails while a vulnerable dependency version is on the test
                  classpath.

                ## Use them

                1. Copy `src/test/java/secpipe` into the scanned project's `src/test/java/`.
                2. Make sure the project has `org.junit.jupiter:junit-jupiter` (includes `junit-jupiter-params`) as a
                   test dependency.
                3. Run `mvn test` (or `gradle test`) from the project root. Tests fail until the issues are fixed.
                4. After fixing, re-run `secpipe verify <project> --baseline secpipe-out/report.json` to confirm.
                """.formatted(ctx.root());
    }

    // ---- helpers -------------------------------------------------------------------------------

    static String className(Finding f) {
        String file = fileName(f.getFile()).replace(".java", "");
        String cwe = f.primaryCwe() == null ? "Rule" : f.primaryCwe().replace("-", "");
        String name = (file + "_" + cwe + "_L" + f.getLine() + "SecurityTest").replaceAll("[^A-Za-z0-9_]", "_");
        return Character.isJavaIdentifierStart(name.charAt(0)) ? name : "T" + name;
    }

    private static String uniqueName(Set<String> used, String name) {
        String candidate = name;
        for (int i = 2; !used.add(candidate); i++) candidate = name.replace("SecurityTest", "_" + i + "SecurityTest");
        return candidate;
    }

    private static String fileName(String path) {
        return path == null ? "" : path.substring(path.lastIndexOf('/') + 1);
    }

    static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c > 0x7e) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    private static String javadoc(String s) {
        return s == null ? "" : s.replace("*/", "* /").replace("\n", " ");
    }

    private static void write(Path file, String content) throws IOException {
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static Map<String, Template> loadTemplates() {
        try (InputStream in = TestGenAgent.class.getResourceAsStream("/knowledge/test-templates.json")) {
            if (in == null) throw new IllegalStateException("missing /knowledge/test-templates.json");
            JsonNode root = Json.MAPPER.readTree(in).path("templates");
            Map<String, Template> out = new LinkedHashMap<>();
            root.fields().forEachRemaining(e -> {
                JsonNode n = e.getValue();
                List<String> payloads = null;
                if (n.has("payloads")) {
                    payloads = new ArrayList<>();
                    for (JsonNode p : n.path("payloads")) payloads.add(p.asText());
                }
                out.put(e.getKey(), new Template(n.path("label").asText(), n.path("vulnerable").asText(),
                        n.path("mitigation").asText(null), payloads, n.path("behaviour").asText(), n.path("assertion").asText(null)));
            });
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
