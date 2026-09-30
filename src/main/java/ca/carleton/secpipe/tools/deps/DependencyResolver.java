package ca.carleton.secpipe.tools.deps;

import ca.carleton.secpipe.agents.ProjectDetector;
import ca.carleton.secpipe.core.BuildTool;
import ca.carleton.secpipe.core.DependencyRef;
import ca.carleton.secpipe.core.ScanConfig;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.tools.ScanException;
import ca.carleton.secpipe.util.Proc;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves the project's third-party dependencies, preferring the real build tool (which includes
 * transitive dependencies) and falling back to parsing manifests directly.
 */
public class DependencyResolver {

    public record Resolution(List<DependencyRef> dependencies, String method, String manifest, List<String> warnings) {
    }

    private static final Pattern GRADLE_TREE = Pattern.compile(
            "[+\\\\]--- ([\\w.\\-]+):([\\w.\\-]+):([\\w.\\-]+)(?: -> ([\\w.\\-]+))?");
    private static final Pattern GRADLE_DECL = Pattern.compile(
            "(?:implementation|api|compile|runtimeOnly|compileOnly|runtime)\\s*\\(?\\s*['\"]([^:'\"\\s]+):([^:'\"\\s]+):([^'\"\\s]+)['\"]");
    private static final Pattern PROPERTY = Pattern.compile("\\$\\{([^}]+)}");

    public Resolution resolve(ScanContext ctx) throws ScanException {
        Path root = ctx.root();
        ScanConfig.DependencyResolution mode = ctx.config().getDependencyResolution();
        BuildTool tool = ctx.profile().buildTool();
        List<String> warnings = new ArrayList<>();
        String manifest = ctx.profile().manifests().isEmpty() ? "pom.xml"
                : ctx.profile().relativize(ctx.profile().manifests().get(0));

        if (mode != ScanConfig.DependencyResolution.MANIFEST && tool != BuildTool.NONE) {
            List<String> cmd = ProjectDetector.buildCommand(root, tool);
            if (cmd == null) {
                String msg = "no runnable " + tool.label() + " found; parsing manifests instead (transitive dependencies are not included)";
                if (mode == ScanConfig.DependencyResolution.BUILD) throw new ScanException(msg);
                warnings.add(msg);
            } else {
                try {
                    List<DependencyRef> deps = tool.isMaven() ? viaMaven(cmd, root, ctx) : viaGradle(cmd, root);
                    if (!deps.isEmpty()) return new Resolution(deps, tool.label() + " (with transitive dependencies)", manifest, warnings);
                    warnings.add(tool.label() + " returned no dependencies; parsing manifests instead");
                } catch (ScanException e) {
                    if (mode == ScanConfig.DependencyResolution.BUILD) throw e;
                    warnings.add(e.getMessage() + "; parsing manifests instead");
                }
            }
        }
        List<DependencyRef> deps = fromManifests(ctx.profile().manifests());
        return new Resolution(deps, "manifest parsing (direct dependencies only)", manifest, warnings);
    }

    private List<DependencyRef> viaMaven(List<String> base, Path root, ScanContext ctx) throws ScanException {
        Path out;
        try {
            out = Files.createTempFile("secpipe-deps", ".txt");
            Files.delete(out);
        } catch (IOException e) {
            throw new ScanException("cannot create temp file: " + e.getMessage(), e);
        }
        List<String> cmd = new ArrayList<>(base);
        cmd.addAll(List.of("-B", "-q", "dependency:list", "-DincludeScope=runtime", "-DappendOutput=true",
                "-DoutputFile=" + out.toAbsolutePath(), "-DoutputAbsoluteArtifactFilename=false"));
        ctx.console().debug("resolving dependencies: " + String.join(" ", cmd));
        try {
            Proc.Result r = Proc.run(cmd, root, Duration.ofMinutes(5));
            if (r.timedOut()) throw new ScanException("Maven dependency resolution timed out");
            if (!r.ok() || !Files.exists(out)) {
                String detail = (r.stdout() + r.stderr()).lines().filter(l -> l.contains("ERROR")).findFirst().orElse("exit code " + r.exitCode());
                throw new ScanException("Maven dependency resolution failed (" + detail.strip() + ")");
            }
            Map<String, DependencyRef> deps = new LinkedHashMap<>();
            for (String line : Files.readAllLines(out)) {
                String t = line.strip();
                if (t.isEmpty() || t.startsWith("The following") || t.equals("none")) continue;
                String coord = t.split("\\s+")[0];
                String[] p = coord.split(":");
                if (p.length < 5) continue;
                String version = p.length >= 6 ? p[4] : p[3];
                deps.putIfAbsent(p[0] + ":" + p[1] + ":" + version, new DependencyRef(p[0], p[1], version, null));
            }
            return new ArrayList<>(deps.values());
        } catch (IOException e) {
            throw new ScanException("could not run Maven: " + e.getMessage(), e);
        } finally {
            try {
                Files.deleteIfExists(out);
            } catch (IOException ignored) {
                // temp file cleanup is best effort
            }
        }
    }

    private List<DependencyRef> viaGradle(List<String> base, Path root) throws ScanException {
        List<String> cmd = new ArrayList<>(base);
        cmd.addAll(List.of("-q", "dependencies", "--configuration", "runtimeClasspath"));
        try {
            Proc.Result r = Proc.run(cmd, root, Duration.ofMinutes(5));
            if (!r.ok()) throw new ScanException("Gradle dependency resolution failed (exit code " + r.exitCode() + ")");
            Map<String, DependencyRef> deps = new LinkedHashMap<>();
            Matcher m = GRADLE_TREE.matcher(r.stdout());
            while (m.find()) {
                String version = m.group(4) != null ? m.group(4) : m.group(3);
                deps.putIfAbsent(m.group(1) + ":" + m.group(2) + ":" + version, new DependencyRef(m.group(1), m.group(2), version, null));
            }
            return new ArrayList<>(deps.values());
        } catch (IOException e) {
            throw new ScanException("could not run Gradle: " + e.getMessage(), e);
        }
    }

    public List<DependencyRef> fromManifests(List<Path> manifests) {
        Map<String, String> props = new HashMap<>();
        Map<String, String> managed = new HashMap<>();
        List<Document> poms = new ArrayList<>();
        for (Path m : manifests) {
            if (!m.getFileName().toString().equals("pom.xml")) continue;
            Document doc = parseXml(m);
            if (doc == null) continue;
            poms.add(doc);
            Element project = doc.getDocumentElement();
            Element properties = child(project, "properties");
            if (properties != null) {
                NodeList nl = properties.getChildNodes();
                for (int i = 0; i < nl.getLength(); i++) {
                    if (nl.item(i) instanceof Element e) props.putIfAbsent(e.getTagName(), e.getTextContent().strip());
                }
            }
            String version = text(project, "version");
            Element parent = child(project, "parent");
            if (version == null && parent != null) version = text(parent, "version");
            if (version != null) props.putIfAbsent("project.version", version);
        }
        for (Document doc : poms) {
            Element dm = child(doc.getDocumentElement(), "dependencyManagement");
            Element list = dm == null ? null : child(dm, "dependencies");
            for (Element d : children(list, "dependency")) {
                String g = interpolate(text(d, "groupId"), props);
                String a = interpolate(text(d, "artifactId"), props);
                String v = interpolate(text(d, "version"), props);
                if (g != null && a != null && v != null) managed.putIfAbsent(g + ":" + a, v);
            }
        }
        Map<String, DependencyRef> out = new LinkedHashMap<>();
        for (Document doc : poms) {
            for (Element d : children(child(doc.getDocumentElement(), "dependencies"), "dependency")) {
                String scope = text(d, "scope");
                if ("test".equals(scope) || "system".equals(scope)) continue;
                String g = interpolate(text(d, "groupId"), props);
                String a = interpolate(text(d, "artifactId"), props);
                String v = interpolate(text(d, "version"), props);
                if (v == null && g != null && a != null) v = managed.get(g + ":" + a);
                if (g == null || a == null || v == null || v.contains("${")) continue;
                out.putIfAbsent(g + ":" + a + ":" + v, new DependencyRef(g, a, v, null));
            }
        }
        for (Path m : manifests) {
            if (!m.getFileName().toString().startsWith("build.gradle")) continue;
            try {
                Matcher matcher = GRADLE_DECL.matcher(Files.readString(m));
                while (matcher.find()) {
                    String v = matcher.group(3);
                    if (v.contains("$")) continue;
                    out.putIfAbsent(matcher.group(1) + ":" + matcher.group(2) + ":" + v,
                            new DependencyRef(matcher.group(1), matcher.group(2), v, null));
                }
            } catch (IOException ignored) {
                // unreadable manifest: nothing to add
            }
        }
        return new ArrayList<>(out.values());
    }

    private static String interpolate(String value, Map<String, String> props) {
        if (value == null) return null;
        String v = value;
        for (int i = 0; i < 5 && v.contains("${"); i++) {
            Matcher m = PROPERTY.matcher(v);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                String replacement = props.getOrDefault(m.group(1), m.group(0));
                m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
            m.appendTail(sb);
            if (sb.toString().equals(v)) break;
            v = sb.toString();
        }
        return v;
    }

    private static Document parseXml(Path file) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setExpandEntityReferences(false);
            DocumentBuilder b = f.newDocumentBuilder();
            return b.parse(file.toFile());
        } catch (Exception e) {
            return null;
        }
    }

    private static Element child(Element parent, String name) {
        if (parent == null) return null;
        NodeList nl = parent.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            if (n instanceof Element e && e.getTagName().equals(name)) return e;
        }
        return null;
    }

    private static List<Element> children(Element parent, String name) {
        List<Element> out = new ArrayList<>();
        if (parent == null) return out;
        NodeList nl = parent.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            if (nl.item(i) instanceof Element e && e.getTagName().equals(name)) out.add(e);
        }
        return out;
    }

    private static String text(Element parent, String name) {
        Element e = child(parent, name);
        return e == null ? null : e.getTextContent().strip();
    }
}
