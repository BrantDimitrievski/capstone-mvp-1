// makes changed copies of owasp benchmark test cases, so we can check secpipe isn't just recognising them
//
//   mutate: same logic, different look. renames the class, package, locals, params and helper methods,
//           strips comments and shuffles the order of class members
//   inject: takes a SAFE case and adds one line (bar = param;) right before the sink, so tainted input
//           reaches it. the case becomes really vulnerable, then gets mutated like above
//
// usage (from the repo root, uses the javaparser that's already inside secpipe.jar):
//   java -cp target/secpipe.jar eval/mutate/Mutator.java <BenchmarkJava dir> <out dir> <mutate|inject> [seed]
// writes <out dir>/src/main/java/com/app/handlers/*.java, <out dir>/pom.xml and <out dir>/labels.csv

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.comments.Comment;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.Statement;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public class Mutator {

    // categories secpipe has rules for, and the cwe benchmark uses for each
    static final Map<String, String> CWE = Map.of(
            "sqli", "89", "cmdi", "78", "pathtraver", "22", "crypto", "327", "hash", "328");
    // injection only makes sense where safety comes from the data flow
    static final Set<String> INJECTABLE = Set.of("sqli", "cmdi", "pathtraver");

    static final String[] WORDS = {"Order", "Invoice", "Report", "Account", "Profile", "Ticket", "Upload",
            "Search", "Export", "Session", "Billing", "Catalog", "Review", "Notice", "Audit", "Member"};

    public static void main(String[] args) throws IOException {
        if (args.length < 3) {
            System.err.println("usage: Mutator <BenchmarkJava dir> <out dir> <mutate|inject> [seed]");
            System.exit(2);
        }
        Path bench = Path.of(args[0]);
        Path out = Path.of(args[1]);
        String mode = args[2];
        long seed = args.length > 3 ? Long.parseLong(args[3]) : 4907;
        Random rnd = new Random(seed);

        StaticJavaParser.setConfiguration(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));

        Path src = bench.resolve("src/main/java/org/owasp/benchmark/testcode");
        Path dest = out.resolve("src/main/java/com/app/handlers");
        Files.createDirectories(dest);
        Files.writeString(out.resolve("pom.xml"), POM);

        List<String[]> labels = new ArrayList<>();
        Set<String> usedNames = new HashSet<>();
        int skipped = 0;

        for (String line : Files.readAllLines(bench.resolve("expectedresults-1.2.csv"))) {
            if (line.startsWith("#")) continue;
            String[] p = line.split(",");
            String test = p[0].trim(), cat = p[1].trim();
            boolean vulnerable = p[2].trim().equals("true");
            if (!CWE.containsKey(cat)) continue;
            if (mode.equals("inject") && (vulnerable || !INJECTABLE.contains(cat))) continue;

            CompilationUnit cu = StaticJavaParser.parse(src.resolve(test + ".java"));
            if (mode.equals("inject")) {
                if (!inject(cu)) {
                    skipped++;
                    continue;
                }
                vulnerable = true;
            }

            String newName;
            do {
                newName = WORDS[rnd.nextInt(WORDS.length)] + "Handler" + (100 + rnd.nextInt(9000));
            } while (!usedNames.add(newName));

            mutate(cu, test, newName, rnd);
            String code = cu.toString()
                    .replace("org.owasp.benchmark.helpers", "com.app.util")
                    .replace("org.owasp.benchmark", "com.app");
            Files.writeString(dest.resolve(newName + ".java"), code);
            labels.add(new String[]{newName + ".java", test, cat, CWE.get(cat), String.valueOf(vulnerable)});
        }

        StringBuilder csv = new StringBuilder("file,original,category,cwe,vulnerable\n");
        for (String[] l : labels) csv.append(String.join(",", l)).append('\n');
        Files.writeString(out.resolve("labels.csv"), csv.toString());
        System.out.println(mode + ": wrote " + labels.size() + " files to " + dest
                + (skipped > 0 ? " (skipped " + skipped + " that didn't fit the injection pattern)" : ""));
    }

    // adds "bar = param;" right before the last top-level statement in doPost that reads bar (the sink)
    static boolean inject(CompilationUnit cu) {
        MethodDeclaration doPost = cu.findFirst(MethodDeclaration.class,
                m -> m.getNameAsString().equals("doPost")).orElse(null);
        if (doPost == null || doPost.getBody().isEmpty()) return false;
        NodeList<Statement> stmts = doPost.getBody().get().getStatements();

        if (!declaresString(stmts, "param") || !declaresString(stmts, "bar")) return false;

        int sink = -1;
        for (int i = 0; i < stmts.size(); i++) {
            if (readsName(stmts.get(i), "bar")) sink = i;
        }
        if (sink < 0) return false;
        stmts.add(sink, StaticJavaParser.parseStatement("bar = param;"));
        return true;
    }

    static boolean declaresString(NodeList<Statement> stmts, String name) {
        for (Statement s : stmts) {
            if (!s.isExpressionStmt()) continue;
            var e = s.asExpressionStmt().getExpression();
            if (e instanceof VariableDeclarationExpr v) {
                for (VariableDeclarator d : v.getVariables()) {
                    if (d.getNameAsString().equals(name) && d.getTypeAsString().equals("String")) return true;
                }
            }
        }
        return false;
    }

    static boolean readsName(Node n, String name) {
        for (NameExpr e : n.findAll(NameExpr.class)) {
            if (!e.getNameAsString().equals(name)) continue;
            boolean isTarget = e.getParentNode()
                    .filter(par -> par instanceof AssignExpr a && a.getTarget() == e
                            && a.getOperator() == AssignExpr.Operator.ASSIGN)
                    .isPresent();
            if (!isTarget) return true;
        }
        return false;
    }

    static void mutate(CompilationUnit cu, String oldName, String newName, Random rnd) {
        // comments go, they can give away where the file came from
        for (Comment c : cu.getAllContainedComments()) c.remove();
        cu.getComment().ifPresent(Comment::remove);

        cu.setPackageDeclaration("com.app.handlers");

        // class name, plus string literals that carry it (servlet url, header names)
        for (TypeDeclaration<?> t : cu.getTypes()) {
            if (t.getNameAsString().equals(oldName)) t.setName(newName);
        }
        for (StringLiteralExpr s : cu.findAll(StringLiteralExpr.class)) {
            if (s.getValue().contains(oldName)) s.setValue(s.getValue().replace(oldName, newName));
            if (s.getValue().contains("BenchmarkTest")) s.setValue(s.getValue().replaceAll("BenchmarkTest\\d*", newName));
        }

        // locals + params get new names. skip anything that is also a field, so nothing changes meaning
        Set<String> fields = new HashSet<>();
        for (FieldDeclaration f : cu.findAll(FieldDeclaration.class)) {
            for (VariableDeclarator v : f.getVariables()) fields.add(v.getNameAsString());
        }
        Map<String, String> rename = new HashMap<>();
        int n = 0;
        for (VariableDeclarator v : cu.findAll(VariableDeclarator.class)) {
            if (v.getParentNode().orElse(null) instanceof FieldDeclaration) continue;
            String name = v.getNameAsString();
            if (!fields.contains(name) && !rename.containsKey(name)) rename.put(name, "v" + (n++) + "_" + rnd.nextInt(100));
        }
        for (Parameter p : cu.findAll(Parameter.class)) {
            String name = p.getNameAsString();
            if (!fields.contains(name) && !rename.containsKey(name)) rename.put(name, "v" + (n++) + "_" + rnd.nextInt(100));
        }
        for (VariableDeclarator v : cu.findAll(VariableDeclarator.class)) {
            if (rename.containsKey(v.getNameAsString())) v.setName(rename.get(v.getNameAsString()));
        }
        for (Parameter p : cu.findAll(Parameter.class)) {
            if (rename.containsKey(p.getNameAsString())) p.setName(rename.get(p.getNameAsString()));
        }
        for (NameExpr e : cu.findAll(NameExpr.class)) {
            if (rename.containsKey(e.getNameAsString())) e.setName(rename.get(e.getNameAsString()));
        }

        // the benchmark's own helper method name
        String helper = "process" + (100 + rnd.nextInt(900));
        for (MethodDeclaration m : cu.findAll(MethodDeclaration.class)) {
            if (m.getNameAsString().equals("doSomething")) m.setName(helper);
        }
        for (MethodCallExpr c : cu.findAll(MethodCallExpr.class)) {
            if (c.getNameAsString().equals("doSomething")) c.setName(helper);
        }

        // member order doesn't matter in java, so shuffle it
        for (TypeDeclaration<?> t : cu.findAll(TypeDeclaration.class)) {
            List<BodyDeclaration<?>> members = new ArrayList<>(t.getMembers());
            Collections.shuffle(members, rnd);
            t.getMembers().clear();
            members.forEach(t::addMember);
        }
    }

    static final String POM = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.app</groupId>
                <artifactId>handlers</artifactId>
                <version>0.1.0</version>
                <packaging>war</packaging>
                <dependencies>
                    <dependency>
                        <groupId>javax.servlet</groupId>
                        <artifactId>javax.servlet-api</artifactId>
                        <version>4.0.1</version>
                        <scope>provided</scope>
                    </dependency>
                </dependencies>
            </project>
            """;
}
