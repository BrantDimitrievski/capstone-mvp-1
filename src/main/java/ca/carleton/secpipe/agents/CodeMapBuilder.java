package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.CodeMap;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

/** Builds the {@link CodeMap} and detects frameworks from parsed sources. */
final class CodeMapBuilder {

    private static final Set<String> MAPPING_ANNOTATIONS = Set.of(
            "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping",
            "GET", "POST", "PUT", "DELETE", "PATCH", "Path");
    private static final Set<String> SERVLET_METHODS = Set.of("doGet", "doPost", "doPut", "doDelete", "doPatch", "service");
    private static final Set<String> SOURCE_ANNOTATIONS = Set.of(
            "RequestParam", "PathVariable", "RequestHeader", "RequestBody", "CookieValue", "RequestPart",
            "ModelAttribute", "PathParam", "QueryParam", "FormParam", "HeaderParam");
    private static final Set<String> SOURCE_CALLS = Set.of(
            "getParameter", "getParameterValues", "getParameterMap", "getHeader", "getQueryString", "getPathInfo",
            "getRequestURI", "getCookies", "getInputStream", "getReader", "getPart");

    private static final Map<String, String> FRAMEWORK_IMPORTS = Map.ofEntries(
            Map.entry("org.springframework.boot", "Spring Boot"),
            Map.entry("org.springframework.web", "Spring MVC"),
            Map.entry("org.springframework.security", "Spring Security"),
            Map.entry("org.springframework.jdbc", "Spring JDBC"),
            Map.entry("javax.servlet", "Servlet API"),
            Map.entry("jakarta.servlet", "Servlet API"),
            Map.entry("javax.ws.rs", "JAX-RS"),
            Map.entry("jakarta.ws.rs", "JAX-RS"),
            Map.entry("javax.persistence", "JPA"),
            Map.entry("jakarta.persistence", "JPA"),
            Map.entry("org.hibernate", "Hibernate"),
            Map.entry("java.sql", "JDBC"),
            Map.entry("io.jsonwebtoken", "JJWT"),
            Map.entry("com.auth0.jwt", "java-jwt"),
            Map.entry("org.apache.struts", "Struts"),
            Map.entry("io.micronaut", "Micronaut"),
            Map.entry("io.quarkus", "Quarkus"));

    private CodeMapBuilder() {
    }

    static CodeMap build(Map<Path, CompilationUnit> sources, Function<Path, String> relativize) {
        CodeMap map = new CodeMap();
        int classes = 0;
        for (Map.Entry<Path, CompilationUnit> e : sources.entrySet()) {
            String file = relativize.apply(e.getKey());
            CompilationUnit cu = e.getValue();
            classes += cu.findAll(TypeDeclaration.class).size();
            List<CodeMap.MethodInfo> methods = new ArrayList<>();
            for (CallableDeclaration<?> c : cu.findAll(CallableDeclaration.class)) {
                @SuppressWarnings("unchecked")
                Optional<TypeDeclaration<?>> owner = c.findAncestor(TypeDeclaration.class).map(t -> (TypeDeclaration<?>) t);
                String className = owner.map(t -> t.getNameAsString()).orElse("?");
                boolean servlet = owner.filter(t -> t instanceof ClassOrInterfaceDeclaration)
                        .map(t -> ((ClassOrInterfaceDeclaration) t).getExtendedTypes().stream()
                                .anyMatch(x -> x.getNameAsString().endsWith("HttpServlet")))
                        .orElse(false);
                Optional<AnnotationExpr> mapping = c.getAnnotations().stream()
                        .filter(a -> MAPPING_ANNOTATIONS.contains(a.getName().getIdentifier())).findFirst();
                boolean endpoint = mapping.isPresent() || (servlet && SERVLET_METHODS.contains(c.getNameAsString()));
                String route = null;
                if (endpoint) {
                    String classRoute = owner.flatMap(t -> t.getAnnotations().stream()
                            .filter(a -> Set.of("RequestMapping", "Path", "WebServlet").contains(a.getName().getIdentifier()))
                            .findFirst()).map(CodeMapBuilder::annotationValue).orElse("");
                    String methodRoute = mapping.map(CodeMapBuilder::annotationValue).orElse("");
                    String verb = mapping.map(a -> a.getName().getIdentifier().replace("Mapping", "").toUpperCase())
                            .orElse(c.getNameAsString().startsWith("do") ? c.getNameAsString().substring(2).toUpperCase() : "ANY");
                    if (verb.equals("REQUEST")) verb = "ANY";
                    String path = (classRoute + methodRoute).replace("//", "/");
                    route = verb + " " + (path.isEmpty() ? "/" : path);
                }
                boolean reads = c.getParameters().stream().anyMatch(p -> p.getAnnotations().stream()
                        .anyMatch(a -> SOURCE_ANNOTATIONS.contains(a.getName().getIdentifier())))
                        || c.findAll(MethodCallExpr.class).stream().anyMatch(m -> SOURCE_CALLS.contains(m.getNameAsString()));
                int begin = c.getBegin().map(p -> p.line).orElse(0);
                int end = c.getEnd().map(p -> p.line).orElse(begin);
                methods.add(new CodeMap.MethodInfo(file, className, c.getNameAsString(), begin, end, endpoint, route, reads));
            }
            map.addMethods(file, methods);
        }
        map.setClassCount(classes);
        return map;
    }

    static Set<String> frameworks(Map<Path, CompilationUnit> sources) {
        Set<String> out = new TreeSet<>();
        for (CompilationUnit cu : sources.values()) {
            cu.getImports().forEach(i -> {
                String name = i.getNameAsString();
                FRAMEWORK_IMPORTS.forEach((prefix, label) -> {
                    if (name.startsWith(prefix)) out.add(label);
                });
            });
        }
        return out;
    }

    private static String annotationValue(AnnotationExpr a) {
        if (a instanceof SingleMemberAnnotationExpr s) return clean(s.getMemberValue().toString());
        if (a instanceof NormalAnnotationExpr n) {
            return n.getPairs().stream()
                    .filter(p -> p.getNameAsString().equals("value") || p.getNameAsString().equals("path")
                            || p.getNameAsString().equals("urlPatterns"))
                    .findFirst().map(p -> clean(p.getValue().toString())).orElse("");
        }
        return "";
    }

    private static String clean(String v) {
        String s = v.replace("{", "").replace("}", "").replace("\"", "").strip();
        int comma = s.indexOf(',');
        return comma > 0 ? s.substring(0, comma).strip() : s;
    }
}
