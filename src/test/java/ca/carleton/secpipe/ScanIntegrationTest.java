package ca.carleton.secpipe;

import ca.carleton.secpipe.cli.SecPipeCli;
import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.core.Severity;
import ca.carleton.secpipe.testing.GeneratedTests;
import ca.carleton.secpipe.testing.MockOsvServer;
import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanIntegrationTest {

    static final Path SAMPLE = Path.of("samples/vulnerable-java-app");
    static final String SAMPLE_SRC = "src/main/java/com/example/vulnlab/";

    @TempDir
    static Path tmp;

    static MockOsvServer osv;
    static Path out;
    static int exitCode;
    static ScanResult result;

    @BeforeAll
    static void scanSample() throws Exception {
        osv = MockOsvServer.start(tmp.resolve("cache"));
        out = tmp.resolve("out");
        exitCode = SecPipeCli.execute("scan", SAMPLE.toString(), "--no-ai", "--deps-from", "manifest",
                "--tools", "builtin,pmd,osv", "-o", out.toString(), "-q");
        result = Json.MAPPER.readValue(out.resolve("report.json").toFile(), ScanResult.class);
    }

    @AfterAll
    static void stop() {
        osv.close();
    }

    @Test
    void failsTheBuildOnHighFindings() {
        assertEquals(SecPipeCli.EXIT_FINDINGS, exitCode);
        assertTrue(osv.requestCount() > 0, "dependency agent should have queried the (mock) OSV API");
    }

    @Test
    void detectsEverySeededCodeVulnerability() {
        Map<String, Set<String>> cwesByFile = result.getFindings().stream()
                .filter(f -> f.getCategory() == Category.CODE)
                .collect(Collectors.groupingBy(f -> Path.of(f.getFile()).getFileName().toString(),
                        Collectors.flatMapping(f -> f.getCwes().stream(), Collectors.toSet())));

        assertContains(cwesByFile, "LoginServlet.java", "CWE-89", "CWE-798", "CWE-209");
        assertContains(cwesByFile, "UserDao.java", "CWE-89");
        assertContains(cwesByFile, "FileDownloadServlet.java", "CWE-22");
        assertContains(cwesByFile, "PingServlet.java", "CWE-78");
        assertContains(cwesByFile, "JwtUtil.java", "CWE-321");
        assertContains(cwesByFile, "CryptoUtil.java", "CWE-327", "CWE-328");
        assertContains(cwesByFile, "SessionRestoreServlet.java", "CWE-502");
        assertContains(cwesByFile, "AppConfig.java", "CWE-798");
    }

    @Test
    void mapsAndRanksFindings() {
        for (Finding f : result.getFindings()) {
            assertTrue(f.getId().matches("SP-\\d{3}"), f.getId());
            assertTrue(f.getOwasp() != null && f.getOwasp().matches("A\\d\\d:2021.*"), "OWASP for " + f.getId());
            assertTrue(f.getFix() != null && !f.getFix().isBlank(), "fix for " + f.getId());
            assertTrue(f.getScore() > 0 && f.getScore() <= 10, "score for " + f.getId());
        }
        List<Double> scores = result.getFindings().stream().map(Finding::getScore).toList();
        assertEquals(scores.stream().sorted((a, b) -> Double.compare(b, a)).toList(), scores, "sorted by score");
        Finding sqli = result.getFindings().stream()
                .filter(f -> f.getFile().endsWith("LoginServlet.java") && f.getCwes().contains("CWE-89")).findFirst().orElseThrow();
        assertEquals(Severity.CRITICAL, sqli.getSeverity());
        assertEquals("A03:2021", sqli.getOwasp().substring(0, 8));
    }

    @Test
    void safeCodeIsNotFlagged() throws Exception {
        assertNoFindingsIn("UserDao.java", "findByIdSafe");
        assertNoFindingsIn("PingServlet.java", "uptime");
        assertNoFindingsIn("CryptoUtil.java", "checksum");
        List<Integer> appConfigLines = result.getFindings().stream()
                .filter(f -> f.getFile().endsWith("AppConfig.java")).map(Finding::getLine).toList();
        assertFalse(appConfigLines.contains(7) || appConfigLines.contains(8), "PASSWORD_PARAM/label are not secrets");
    }

    @Test
    void findsVulnerableDependenciesWithFixVersions() {
        Map<String, Finding> deps = result.getFindings().stream()
                .filter(f -> f.getCategory() == Category.DEPENDENCIES)
                .collect(Collectors.toMap(f -> f.getDependency().artifact(), f -> f));
        assertEquals(Set.of("log4j-core", "commons-collections"), deps.keySet());

        Finding log4j = deps.get("log4j-core");
        assertTrue(log4j.getCves().contains("CVE-2021-44228"));
        assertEquals(Severity.CRITICAL, log4j.getSeverity());
        assertEquals("2.15.0", log4j.getDependency().fixedVersion());
        assertTrue(log4j.getOwasp().startsWith("A06:2021"));

        Finding collections = deps.get("commons-collections");
        assertTrue(collections.getCves().contains("CVE-2015-7501"));
        assertEquals("3.2.2", collections.getDependency().fixedVersion());
        assertEquals(Severity.CRITICAL, collections.getSeverity(), "CVSS 9.8 maps to critical");
    }

    @Test
    void writesAllReportFormats() throws Exception {
        byte[] csvBytes = Files.readAllBytes(out.resolve("findings.csv"));
        assertEquals((byte) 0xEF, csvBytes[0], "CSV starts with a UTF-8 BOM so Excel detects the encoding");
        String csv = new String(csvBytes, StandardCharsets.UTF_8).substring(1);
        try (Reader r = new StringReader(csv);
             CSVParser parser = CSVFormat.EXCEL.builder().setHeader().setSkipHeaderRecord(true).get().parse(r)) {
            List<CSVRecord> rows = parser.getRecords();
            assertEquals(result.getFindings().size(), rows.size());
            assertEquals("ID", parser.getHeaderNames().get(0));
            assertEquals(22, parser.getHeaderNames().size());
            assertEquals(result.getFindings().get(0).getId(), rows.get(0).get("ID"));
        }

        JsonNode sarif = Json.MAPPER.readTree(out.resolve("report.sarif").toFile());
        assertEquals("2.1.0", sarif.path("version").asText());
        assertEquals(result.getFindings().size(), sarif.path("runs").path(0).path("results").size());

        String html = Files.readString(out.resolve("report.html"));
        assertFalse(html.contains("__SECPIPE_DATA__"));
        assertTrue(html.contains("CVE-2021-44228"));
        assertFalse(html.contains("<script>alert"), "report data must not inject markup");

        String md = Files.readString(out.resolve("report.md"));
        assertTrue(md.contains("CWE-89") && md.contains("log4j-core"));

        assertTrue(result.getStageTimingsMs().keySet().containsAll(
                List.of("profile", "code-analysis", "dependency-analysis", "triage", "total")));
    }

    @Test
    void generatedRegressionTestsCompile() throws Exception {
        List<Path> sources = GeneratedTests.sources(out);
        assertTrue(sources.stream().anyMatch(p -> p.getFileName().toString().startsWith("LoginServlet_CWE89_")));
        assertTrue(sources.stream().anyMatch(p -> p.getFileName().toString().equals("DependencyVersionsSecurityTest.java")));
        GeneratedTests.compile(out, tmp.resolve("generated-classes"));
    }

    private static void assertContains(Map<String, Set<String>> cwesByFile, String file, String... cwes) {
        Set<String> found = cwesByFile.getOrDefault(file, Set.of());
        for (String cwe : cwes) assertTrue(found.contains(cwe), file + " should report " + cwe + " but had " + found);
    }

    private static void assertNoFindingsIn(String file, String method) throws Exception {
        MethodDeclaration m = StaticJavaParser.parse(SAMPLE.resolve(SAMPLE_SRC + file)).findAll(MethodDeclaration.class).stream()
                .filter(d -> d.getNameAsString().equals(method)).findFirst().orElseThrow();
        int begin = m.getBegin().orElseThrow().line;
        int end = m.getEnd().orElseThrow().line;
        List<Finding> inside = result.getFindings().stream()
                .filter(f -> f.getFile().endsWith(file) && f.getLine() >= begin && f.getLine() <= end).toList();
        assertTrue(inside.isEmpty(), method + "() is safe but was flagged: " + inside.stream().map(Finding::getTitle).toList());
    }
}
