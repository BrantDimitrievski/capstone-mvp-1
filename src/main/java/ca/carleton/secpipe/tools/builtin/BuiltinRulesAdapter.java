package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ProjectProfile;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.tools.ScannerAdapter;
import ca.carleton.secpipe.util.SourceText;
import com.github.javaparser.ast.CompilationUnit;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * secpipe's own JavaParser rules. They need no external tool, so a first scan always produces results.
 */
public class BuiltinRulesAdapter implements ScannerAdapter {

    private final List<JavaRule> rules = List.of(
            new SqlInjectionRule(),
            new PathTraversalRule(),
            new CommandInjectionRule(),
            new HardcodedSecretRule(),
            new WeakCryptoRule(),
            new DeserializationRule());

    @Override
    public String id() {
        return RuleContext.TOOL_ID;
    }

    @Override
    public String displayName() {
        return "secpipe built-in rules (JavaParser)";
    }

    @Override
    public Category category() {
        return Category.CODE;
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public boolean supports(ProjectProfile profile) {
        return "java".equals(profile.language());
    }

    public List<JavaRule> rules() {
        return rules;
    }

    @Override
    public List<Finding> run(ScanContext ctx) {
        List<Finding> out = Collections.synchronizedList(new ArrayList<>());
        ctx.parsedSources().entrySet().parallelStream().forEach(e -> {
            String rel = ctx.profile().relativize(e.getKey());
            out.addAll(analyze(rel, e.getValue(), SourceText.readLines(e.getKey()), ctx.codeMap().fileHandlesRequests(rel), ctx));
        });
        return new ArrayList<>(out);
    }

    public List<Finding> analyze(String relativeFile, CompilationUnit cu, List<String> lines, boolean handlesRequests,
                                 ScanContext ctx) {
        RuleContext rc = new RuleContext(relativeFile, cu, lines, handlesRequests);
        for (JavaRule rule : rules) {
            try {
                rule.check(rc);
            } catch (RuntimeException ex) {
                if (ctx != null) ctx.console().debug("rule " + rule.id() + " failed on " + relativeFile + ": " + ex);
            }
        }
        return rc.findings();
    }

    /** Convenience for tests: analyze parsed sources without a full scan context. */
    public List<Finding> analyzeAll(Path root, Map<Path, CompilationUnit> sources) {
        List<Finding> out = new ArrayList<>();
        sources.forEach((p, cu) -> out.addAll(analyze(root.relativize(p).toString().replace('\\', '/'), cu,
                SourceText.readLines(p), true, null)));
        return out;
    }
}
