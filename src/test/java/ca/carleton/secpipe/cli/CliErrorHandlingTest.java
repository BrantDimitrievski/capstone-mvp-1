package ca.carleton.secpipe.cli;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CliErrorHandlingTest {

    @TempDir
    Path tmp;

    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    private PrintStream originalErr;
    private PrintStream originalOut;

    @BeforeEach
    void capture() {
        originalErr = System.err;
        originalOut = System.out;
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        System.setOut(new PrintStream(stdout, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restore() {
        System.setErr(originalErr);
        System.setOut(originalOut);
    }

    private String output() {
        return stdout.toString(StandardCharsets.UTF_8) + err.toString(StandardCharsets.UTF_8);
    }

    @Test
    void missingPathIsAClearError() {
        int code = SecPipeCli.execute("scan", tmp.resolve("does-not-exist").toString(), "--no-ai", "-o", tmp.resolve("o").toString());
        assertEquals(SecPipeCli.EXIT_ERROR, code);
        assertTrue(output().contains("does-not-exist"), output());
    }

    @Test
    void unsupportedLanguageIsRejected() {
        int code = SecPipeCli.execute("scan", tmp.toString(), "--lang", "python", "--no-ai", "-o", tmp.resolve("o").toString());
        assertEquals(SecPipeCli.EXIT_ERROR, code);
        assertTrue(output().toLowerCase().contains("python"), output());
    }

    @Test
    void directoryWithoutJavaSourcesExplainsWhatToDo() throws Exception {
        Files.writeString(tmp.resolve("notes.txt"), "no code here");
        int code = SecPipeCli.execute("scan", tmp.toString(), "--no-ai", "-o", tmp.resolve("o").toString());
        assertEquals(SecPipeCli.EXIT_ERROR, code);
        assertTrue(output().toLowerCase().contains("java"), output());
    }

    @Test
    void invalidOptionValuesAreErrors() {
        assertEquals(SecPipeCli.EXIT_ERROR, SecPipeCli.execute("scan", tmp.toString(), "--fail-on", "sometimes"));
        assertEquals(SecPipeCli.EXIT_ERROR, SecPipeCli.execute("scan", tmp.toString(), "--category", "everything"));
        assertEquals(SecPipeCli.EXIT_ERROR, SecPipeCli.execute("verify", tmp.toString()));
    }

    @Test
    void failOnNoneAlwaysExitsZero() throws Exception {
        Path src = Files.createDirectories(tmp.resolve("proj/src/main/java/demo"));
        Files.writeString(src.resolve("Hash.java"), """
                package demo;
                class Hash {
                    byte[] h(byte[] d) throws Exception { return java.security.MessageDigest.getInstance("MD5").digest(d); }
                }
                """);
        String[] base = {"scan", tmp.resolve("proj").toString(), "--no-ai", "--category", "code", "--tools", "builtin",
                "--no-tests", "-q", "-o", tmp.resolve("o").toString()};
        assertEquals(SecPipeCli.EXIT_OK, SecPipeCli.execute(concat(base, "--fail-on", "none")));
        assertEquals(SecPipeCli.EXIT_FINDINGS, SecPipeCli.execute(concat(base, "--fail-on", "medium")));
    }

    @Test
    void helpAndVersionSucceed() {
        assertEquals(SecPipeCli.EXIT_OK, SecPipeCli.execute("--help"));
        assertEquals(SecPipeCli.EXIT_OK, SecPipeCli.execute("--version"));
        assertTrue(output().contains(SecPipeCli.version()));
    }

    private static String[] concat(String[] a, String... b) {
        String[] out = new String[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
