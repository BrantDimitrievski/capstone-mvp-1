package ca.carleton.secpipe.testing;

import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

/** Compiles and runs the JUnit tests secpipe generates, the way a user would drop them into their project. */
public final class GeneratedTests {

    public static final String PACKAGE_DIR = "generated-tests/src/test/java/secpipe/generated";

    private GeneratedTests() {
    }

    public static List<Path> sources(Path scanOut) throws IOException {
        try (Stream<Path> s = Files.list(scanOut.resolve(PACKAGE_DIR))) {
            return s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
    }

    /** Compiles every generated test into {@code classesDir}; throws with compiler diagnostics on failure. */
    public static void compile(Path scanOut, Path classesDir) throws IOException {
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        Files.createDirectories(classesDir);
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager fm = javac.getStandardFileManager(diagnostics, null, null)) {
            String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
            List<String> options = List.of("-classpath", classpath, "-d", classesDir.toString(), "-proc:none", "-Xlint:none");
            boolean ok = javac.getTask(null, fm, diagnostics, options, null,
                    fm.getJavaFileObjectsFromPaths(sources(scanOut))).call();
            if (!ok) {
                StringBuilder sb = new StringBuilder("generated tests do not compile:\n");
                diagnostics.getDiagnostics().forEach(d -> sb.append(d).append('\n'));
                throw new AssertionError(sb.toString());
            }
        }
    }

    /** Runs one compiled generated test class against the project at {@code projectRoot}. */
    public static TestExecutionSummary run(Path classesDir, String simpleName, Path projectRoot) throws Exception {
        String previous = System.getProperty("secpipe.projectRoot");
        System.setProperty("secpipe.projectRoot", projectRoot.toAbsolutePath().toString());
        try (URLClassLoader loader = new URLClassLoader(new URL[]{classesDir.toUri().toURL()},
                GeneratedTests.class.getClassLoader())) {
            Class<?> testClass = loader.loadClass("secpipe.generated." + simpleName);
            LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request().selectors(selectClass(testClass)).build();
            Launcher launcher = LauncherFactory.create();
            SummaryGeneratingListener listener = new SummaryGeneratingListener();
            launcher.execute(request, listener);
            return listener.getSummary();
        } finally {
            if (previous == null) System.clearProperty("secpipe.projectRoot");
            else System.setProperty("secpipe.projectRoot", previous);
        }
    }
}
