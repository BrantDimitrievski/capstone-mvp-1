package ca.carleton.secpipe;

import ca.carleton.secpipe.cli.SecPipeCli;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.testing.GeneratedTests;
import ca.carleton.secpipe.testing.MockOsvServer;
import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The remediation loop from the project brief: scan, fix one vulnerability, then prove it with the
 * generated regression test and {@code secpipe verify}.
 */
class VerifyIntegrationTest {

    private static final String LOGIN = "src/main/java/com/example/vulnlab/LoginServlet.java";

    @TempDir
    Path tmp;

    @Test
    void fixingSqlInjectionIsConfirmedByGeneratedTestAndVerify() throws Exception {
        Path project = copy(ScanIntegrationTest.SAMPLE, tmp.resolve("project"));
        Path baselineOut = tmp.resolve("baseline");
        try (MockOsvServer ignored = MockOsvServer.start(tmp.resolve("cache"))) {
            assertEquals(SecPipeCli.EXIT_FINDINGS, SecPipeCli.execute("scan", project.toString(), "--no-ai",
                    "--deps-from", "manifest", "--tools", "builtin,pmd,osv", "-o", baselineOut.toString(), "-q"));
            ScanResult baseline = Json.MAPPER.readValue(baselineOut.resolve("report.json").toFile(), ScanResult.class);
            Finding sqli = baseline.getFindings().stream()
                    .filter(f -> f.getFile().equals(LOGIN) && f.getCwes().contains("CWE-89")).findFirst().orElseThrow();

            Path classes = tmp.resolve("classes");
            GeneratedTests.compile(baselineOut, classes);
            String testClass = GeneratedTests.sources(baselineOut).stream()
                    .map(p -> p.getFileName().toString().replace(".java", ""))
                    .filter(n -> n.startsWith("LoginServlet_CWE89_")).findFirst().orElseThrow();

            TestExecutionSummary before = GeneratedTests.run(classes, testClass, project);
            assertTrue(before.getTotalFailureCount() >= 1, "generated test must fail while the SQL injection is present");

            applyParameterizedQueryFix(project.resolve(LOGIN));

            TestExecutionSummary after = GeneratedTests.run(classes, testClass, project);
            assertEquals(0, after.getTotalFailureCount(), "generated test must pass once the query is parameterized");
            assertTrue(after.getTestsSucceededCount() >= 2);

            Path verifyOut = tmp.resolve("verify");
            int code = SecPipeCli.execute("verify", project.toString(), "-b", baselineOut.resolve("report.json").toString(),
                    "--no-ai", "--deps-from", "manifest", "-o", verifyOut.toString(), "-q");
            assertEquals(SecPipeCli.EXIT_FINDINGS, code, "other high findings are still present");

            JsonNode verify = Json.MAPPER.readTree(verifyOut.resolve("verify.json").toFile());
            assertEquals(1, verify.path("fixed").asInt());
            assertEquals(sqli.getFingerprint(), verify.path("fixedFindings").path(0).path("fingerprint").asText());
            assertEquals(0, verify.path("introduced").asInt(), "shifted line numbers must not look like new findings");
            assertEquals(baseline.getFindings().size() - 1, verify.path("stillPresent").asInt());
            assertTrue(Files.readString(verifyOut.resolve("verify.md")).contains("## Fixed (1)"));

            assertEquals(SecPipeCli.EXIT_OK, SecPipeCli.execute("verify", project.toString(),
                    "-b", baselineOut.resolve("report.json").toString(), "--no-ai", "--deps-from", "manifest",
                    "--fail-on", "none", "-o", verifyOut.toString(), "-q"));
        }
    }

    private static void applyParameterizedQueryFix(Path file) throws IOException {
        String src = Files.readString(file);
        String fixed = src
                .replace("import java.sql.Statement;", "import java.sql.PreparedStatement;")
                .replace("""
                                    Statement stmt = conn.createStatement();
                                    String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
                                    ResultSet rs = stmt.executeQuery(query);
                        """, """
                                    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
                                    stmt.setString(1, username);
                                    stmt.setString(2, password);
                                    ResultSet rs = stmt.executeQuery();
                        """);
        assertTrue(!fixed.equals(src) && fixed.contains("prepareStatement"), "patch did not apply");
        Files.writeString(file, fixed);
    }

    private static Path copy(Path from, Path to) throws IOException {
        try (Stream<Path> walk = Files.walk(from)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                Path target = to.resolve(from.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(target);
                else Files.copy(p, target);
            }
        }
        return to;
    }
}
