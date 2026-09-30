package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BuiltinRulesTest {

    private static final JavaParser PARSER = new JavaParser(
            new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));

    static List<Finding> analyze(String body) {
        return analyze(body, true);
    }

    static List<Finding> analyze(String body, boolean handlesRequests) {
        String source = """
                import java.io.*;
                import java.sql.*;
                import java.nio.file.*;
                import javax.crypto.*;
                import javax.crypto.spec.*;
                import java.security.*;
                import javax.servlet.http.*;
                import javax.net.ssl.*;
                class T {
                %s
                }
                """.formatted(body);
        CompilationUnit cu = PARSER.parse(source).getResult().orElseThrow();
        return new BuiltinRulesAdapter().analyze("src/T.java", cu, source.lines().toList(), handlesRequests, null);
    }

    static List<String> cwes(List<Finding> findings) {
        return findings.stream().map(Finding::primaryCwe).toList();
    }

    @Nested
    class SqlInjection {
        @Test
        void concatenatedRequestParameterIsCritical() {
            List<Finding> f = analyze("""
                    void doGet(HttpServletRequest req, Statement st) throws Exception {
                        String id = req.getParameter("id");
                        st.executeQuery("SELECT * FROM users WHERE id = " + id);
                    }""");
            assertEquals(List.of("CWE-89"), cwes(f));
            assertEquals(Severity.CRITICAL, f.get(0).getSeverity());
            assertEquals(Confidence.HIGH, f.get(0).getConfidence());
            assertEquals(12, f.get(0).getLine());
        }

        @Test
        void queryBuiltInLocalVariableFromParameter() {
            List<Finding> f = analyze("""
                    ResultSet find(Connection c, String name) throws Exception {
                        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
                        return c.createStatement().executeQuery(sql);
                    }""");
            assertEquals(List.of("CWE-89"), cwes(f));
            assertEquals(Confidence.MEDIUM, f.get(0).getConfidence());
        }

        @Test
        void stringBuilderAndFormatAreTracked() {
            assertEquals(List.of("CWE-89"), cwes(analyze("""
                    void a(Statement st, String n) throws Exception {
                        StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE n = '");
                        sb.append(n).append("'");
                        st.execute(sb.toString());
                    }""")));
            assertEquals(List.of("CWE-89"), cwes(analyze("""
                    void a(Statement st, String n) throws Exception {
                        st.executeUpdate(String.format("DELETE FROM t WHERE n = '%s'", n));
                    }""")));
        }

        @Test
        void parameterizedAndConstantQueriesAreNotFlagged() {
            assertTrue(analyze("""
                    static final String BASE = "SELECT * FROM t";
                    void a(Connection c, Statement st, long id) throws Exception {
                        PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE id = ?");
                        ps.setLong(1, id);
                        ps.executeQuery();
                        st.executeQuery("SELECT 1");
                        st.executeQuery(BASE + " WHERE x = 1");
                    }""").isEmpty());
        }
    }

    @Nested
    class PathTraversal {
        @Test
        void requestInputInFileConstructor() {
            List<Finding> f = analyze("""
                    void doGet(HttpServletRequest req) throws Exception {
                        File file = new File("/uploads/", req.getParameter("name"));
                        new FileInputStream(file).read();
                    }""");
            assertEquals(List.of("CWE-22"), cwes(f));
            assertEquals(Severity.HIGH, f.get(0).getSeverity());
        }

        @Test
        void canonicalPathCheckSuppresses() {
            assertTrue(analyze("""
                    void doGet(HttpServletRequest req) throws Exception {
                        File base = new File("/uploads");
                        File file = new File(base, req.getParameter("name"));
                        if (!file.getCanonicalPath().startsWith(base.getCanonicalPath())) throw new SecurityException();
                    }""").isEmpty());
        }

        @Test
        void parameterOnlyFlaggedInRequestHandlingFiles() {
            String body = """
                    byte[] read(String name) throws Exception {
                        return Files.readAllBytes(Paths.get("/data/" + name));
                    }""";
            assertEquals(List.of("CWE-22"), cwes(analyze(body, true)));
            assertTrue(analyze(body, false).isEmpty());
        }
    }

    @Nested
    class CommandInjection {
        @Test
        void runtimeExecWithRequestInput() {
            List<Finding> f = analyze("""
                    void doGet(HttpServletRequest req) throws Exception {
                        Runtime.getRuntime().exec("ping " + req.getParameter("host"));
                    }""");
            assertEquals(List.of("CWE-78"), cwes(f));
            assertEquals(Severity.CRITICAL, f.get(0).getSeverity());
        }

        @Test
        void runtimeVariableAndProcessBuilder() {
            assertEquals(List.of("CWE-78", "CWE-78"), cwes(analyze("""
                    void a(String cmd) throws Exception {
                        Runtime rt = Runtime.getRuntime();
                        rt.exec(cmd);
                        new ProcessBuilder("sh", "-c", cmd).start();
                    }""")));
        }

        @Test
        void constantCommandsAreFine() {
            assertTrue(analyze("""
                    void a() throws Exception {
                        new ProcessBuilder("uptime").start();
                        Runtime.getRuntime().exec(new String[]{"ls", "-la"});
                    }""").isEmpty());
        }
    }

    @Nested
    class Secrets {
        @Test
        void hardCodedPasswordAndToken() {
            List<Finding> f = analyze("""
                    private String dbPassword = "hunter22!";
                    private static final String GITHUB = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
                    void c() throws Exception { DriverManager.getConnection("jdbc:x", "sa", "letmein"); }
                    """);
            assertEquals(List.of("CWE-798", "CWE-798", "CWE-798"), cwes(f));
        }

        @Test
        void hardCodedKeys() {
            List<Finding> f = analyze("""
                    private static final String JWT_SECRET = "super-secret-signing-key";
                    Key k() { return new SecretKeySpec("0123456789abcdef".getBytes(), "AES"); }
                    """);
            assertEquals(List.of("CWE-321", "CWE-321"), cwes(f));
        }

        @Test
        void labelsPlaceholdersAndEnvLookupsAreIgnored() {
            assertTrue(analyze("""
                    static final String PASSWORD_PARAM = "password";
                    static final String PASSWORD_LABEL = "Enter your password";
                    String password = System.getenv("DB_PASSWORD");
                    String apiKey = "${API_KEY}";
                    String token = "";
                    """).isEmpty());
        }
    }

    @Nested
    class Crypto {
        @Test
        void weakHashesAndCiphers() {
            List<Finding> f = analyze("""
                    void a() throws Exception {
                        MessageDigest.getInstance("MD5");
                        Cipher.getInstance("DES/CBC/PKCS5Padding");
                        Cipher.getInstance("AES");
                        SSLContext.getInstance("TLSv1");
                    }""");
            assertEquals(List.of("CWE-328", "CWE-327", "CWE-327", "CWE-327"), cwes(f));
            assertEquals(List.of("SP-JAVA-HASH", "SP-JAVA-CRYPTO", "SP-JAVA-CRYPTO", "SP-JAVA-CRYPTO"),
                    f.stream().map(Finding::getRuleId).toList());
        }

        @Test
        void fullyQualifiedCallsAreRecognised() {
            assertEquals(List.of("CWE-328", "CWE-327"), cwes(analyze("""
                    void a() throws Exception {
                        java.security.MessageDigest.getInstance("SHA-1");
                        javax.crypto.Cipher.getInstance("RC4");
                    }""")));
        }

        @Test
        void strongAlgorithmsAreFine() {
            assertTrue(analyze("""
                    void a() throws Exception {
                        MessageDigest.getInstance("SHA-256");
                        Cipher.getInstance("AES/GCM/NoPadding");
                        SSLContext.getInstance("TLSv1.3");
                    }""").isEmpty());
        }
    }

    @Nested
    class Deserialization {
        @Test
        void objectInputStreamFromRequest() {
            List<Finding> f = analyze("""
                    Object doPost(HttpServletRequest req) throws Exception {
                        return new ObjectInputStream(req.getInputStream()).readObject();
                    }""");
            assertEquals(List.of("CWE-502"), cwes(f));
            assertEquals(Severity.CRITICAL, f.get(0).getSeverity());
        }

        @Test
        void inputFilterSuppresses() {
            assertTrue(analyze("""
                    Object read(InputStream in) throws Exception {
                        ObjectInputStream ois = new ObjectInputStream(in);
                        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.*;!*"));
                        return ois.readObject();
                    }""").isEmpty());
        }
    }
}
