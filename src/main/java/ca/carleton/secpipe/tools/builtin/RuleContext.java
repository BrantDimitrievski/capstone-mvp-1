package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Per-file state shared by the built-in rules. */
public class RuleContext {

    public static final String TOOL_ID = "builtin";

    private final String file;
    private final CompilationUnit cu;
    private final List<String> lines;
    private final boolean fileHandlesRequests;
    private final List<Finding> findings = new ArrayList<>();
    private final Map<Node, TaintTracker> trackers = new IdentityHashMap<>();
    private final Map<String, String> stringConstants = new HashMap<>();
    private final TaintTracker empty = new TaintTracker(null);

    public RuleContext(String file, CompilationUnit cu, List<String> lines, boolean fileHandlesRequests) {
        this.file = file;
        this.cu = cu;
        this.lines = lines;
        this.fileHandlesRequests = fileHandlesRequests;
        cu.findAll(VariableDeclarator.class).forEach(vd -> vd.getInitializer()
                .filter(Expression::isStringLiteralExpr)
                .ifPresent(init -> stringConstants.put(vd.getNameAsString(), init.asStringLiteralExpr().getValue())));
    }

    public CompilationUnit cu() {
        return cu;
    }

    public String file() {
        return file;
    }

    public boolean fileHandlesRequests() {
        return fileHandlesRequests;
    }

    public TaintTracker taintFor(Node node) {
        Optional<CallableDeclaration> callable = node.findAncestor(CallableDeclaration.class);
        return callable.<TaintTracker>map(c -> trackers.computeIfAbsent(c, k -> new TaintTracker((CallableDeclaration<?>) k)))
                .orElse(empty);
    }

    /** Resolves a literal, or a variable/field initialized with a literal, to its string value. */
    public Optional<String> constantString(Expression e) {
        if (e instanceof StringLiteralExpr s) return Optional.of(s.getValue());
        if (e instanceof NameExpr n) return Optional.ofNullable(stringConstants.get(n.getNameAsString()));
        if (e instanceof FieldAccessExpr f) return Optional.ofNullable(stringConstants.get(f.getNameAsString()));
        return Optional.empty();
    }

    public Finding report(Node node, String ruleId, String cwe, Severity severity, Confidence confidence,
                          String title, String message) {
        int line = node.getBegin().map(p -> p.line).orElse(0);
        for (Finding existing : findings) {
            if (existing.getLine() == line && existing.getRuleId().equals(ruleId)) return existing;
        }
        Finding f = Finding.code(TOOL_ID, ruleId, file, line);
        f.addCwe(cwe);
        f.setSeverity(severity);
        f.setConfidence(confidence);
        f.setTitle(title);
        f.setMessage(message);
        if (line > 0 && line <= lines.size()) f.setSnippet(truncate(lines.get(line - 1).strip()));
        findings.add(f);
        return f;
    }

    public List<Finding> findings() {
        return findings;
    }

    static String truncate(String s) {
        return s.length() > 240 ? s.substring(0, 237) + "..." : s;
    }
}
