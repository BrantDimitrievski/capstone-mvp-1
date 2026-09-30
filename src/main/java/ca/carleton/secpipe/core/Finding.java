package ca.carleton.secpipe.core;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The normalized finding every adapter produces. Agents enrich it in place as it moves
 * through the pipeline (knowledge mapping, exploitability, score, generated test, ...).
 */
public class Finding {

    private String id;
    private String fingerprint;
    private Category category = Category.CODE;
    private Set<String> tools = new LinkedHashSet<>();
    private String ruleId;
    private String title;
    private String message;
    private String file;
    private int line;
    private String snippet;
    private List<String> cwes = new ArrayList<>();
    private List<String> cves = new ArrayList<>();
    private String vulnerabilityId;
    private String owasp;
    private Severity severity = Severity.MEDIUM;
    private Confidence confidence = Confidence.MEDIUM;
    private Exploitability exploitability = Exploitability.unknown();
    private double score;
    private String explanation;
    private String fix;
    private String fixSource;
    private List<String> references = new ArrayList<>();
    private DependencyRef dependency;
    private String generatedTest;

    public Finding() {
    }

    public static Finding code(String tool, String ruleId, String file, int line) {
        Finding f = new Finding();
        f.category = Category.CODE;
        f.tools.add(tool);
        f.ruleId = ruleId;
        f.file = file;
        f.line = line;
        return f;
    }

    public static Finding dependency(String tool, String vulnerabilityId, DependencyRef dep, String manifestFile) {
        Finding f = new Finding();
        f.category = Category.DEPENDENCIES;
        f.tools.add(tool);
        f.ruleId = vulnerabilityId;
        f.vulnerabilityId = vulnerabilityId;
        f.dependency = dep;
        f.file = manifestFile;
        f.line = 1;
        return f;
    }

    /** Primary CWE (first in the list), or null. */
    @JsonIgnore
    public String primaryCwe() {
        return cwes.isEmpty() ? null : cwes.get(0);
    }

    /** Preferred identifier for a dependency vulnerability: first CVE if present, else the advisory id. */
    @JsonIgnore
    public String primaryVulnId() {
        return cves.isEmpty() ? vulnerabilityId : cves.get(0);
    }

    /**
     * Stable identity used for de-duplication and for {@code verify} baselines. For code findings it
     * uses the CWE (or rule), file and whitespace-normalized snippet, so unrelated edits that only shift
     * line numbers do not make a finding look "new".
     */
    public String computeFingerprint() {
        String key;
        if (category == Category.DEPENDENCIES) {
            String artifact = dependency == null ? "" : dependency.artifact();
            String version = dependency == null ? "" : dependency.version();
            key = "dep|" + artifact.toLowerCase(Locale.ROOT) + "|" + version + "|" + primaryVulnId();
        } else {
            String kind = primaryCwe() != null ? primaryCwe() : ruleId;
            String normalized = snippet == null || snippet.isBlank()
                    ? "line:" + line
                    : snippet.replaceAll("\\s+", " ").trim();
            key = "code|" + kind + "|" + file + "|" + normalized;
        }
        return sha256(key).substring(0, 16);
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public void addCwe(String cwe) {
        if (cwe != null && !cwe.isBlank() && !cwes.contains(cwe)) cwes.add(cwe);
    }

    public void addCve(String cve) {
        if (cve != null && !cve.isBlank() && !cves.contains(cve)) cves.add(cve);
    }

    public void addReference(String ref) {
        if (ref != null && !ref.isBlank() && !references.contains(ref)) references.add(ref);
    }

    @JsonIgnore
    public String location() {
        return line > 0 ? file + ":" + line : file;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }
    public Category getCategory() { return category; }
    public void setCategory(Category category) { this.category = category; }
    public Set<String> getTools() { return tools; }
    public void setTools(Set<String> tools) { this.tools = new LinkedHashSet<>(tools); }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }
    public int getLine() { return line; }
    public void setLine(int line) { this.line = line; }
    public String getSnippet() { return snippet; }
    public void setSnippet(String snippet) { this.snippet = snippet; }
    public List<String> getCwes() { return cwes; }
    public void setCwes(List<String> cwes) { this.cwes = new ArrayList<>(cwes); }
    public List<String> getCves() { return cves; }
    public void setCves(List<String> cves) { this.cves = new ArrayList<>(cves); }
    public String getVulnerabilityId() { return vulnerabilityId; }
    public void setVulnerabilityId(String vulnerabilityId) { this.vulnerabilityId = vulnerabilityId; }
    public String getOwasp() { return owasp; }
    public void setOwasp(String owasp) { this.owasp = owasp; }
    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public Confidence getConfidence() { return confidence; }
    public void setConfidence(Confidence confidence) { this.confidence = confidence; }
    public Exploitability getExploitability() { return exploitability; }
    public void setExploitability(Exploitability exploitability) { this.exploitability = exploitability; }
    public double getScore() { return score; }
    public void setScore(double score) { this.score = score; }
    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }
    public String getFix() { return fix; }
    public void setFix(String fix) { this.fix = fix; }
    public String getFixSource() { return fixSource; }
    public void setFixSource(String fixSource) { this.fixSource = fixSource; }
    public List<String> getReferences() { return references; }
    public void setReferences(List<String> references) { this.references = new ArrayList<>(references); }
    public DependencyRef getDependency() { return dependency; }
    public void setDependency(DependencyRef dependency) { this.dependency = dependency; }
    public String getGeneratedTest() { return generatedTest; }
    public void setGeneratedTest(String generatedTest) { this.generatedTest = generatedTest; }
}
