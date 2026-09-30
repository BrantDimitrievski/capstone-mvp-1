package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.DependencyRef;
import ca.carleton.secpipe.core.Exploitability;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class TriageAgentTest {

    private static Finding code(String tool, String cwe, int line, Severity severity, Confidence confidence) {
        Finding f = Finding.code(tool, tool + "-rule", "src/A.java", line);
        f.addCwe(cwe);
        f.setSeverity(severity);
        f.setConfidence(confidence);
        f.setSnippet("line " + line);
        return f;
    }

    @Test
    void mergesSameIssueFromTwoToolsAndRaisesConfidence() {
        Finding builtin = code("builtin", "CWE-321", 12, Severity.HIGH, Confidence.MEDIUM);
        Finding pmd = code("pmd", "CWE-798", 12, Severity.MEDIUM, Confidence.MEDIUM);
        pmd.addReference("https://pmd.github.io");

        List<Finding> out = new TriageAgent().triage(List.of(pmd, builtin));

        assertEquals(1, out.size());
        Finding merged = out.get(0);
        assertEquals(Set.of("builtin", "pmd"), merged.getTools());
        assertEquals("builtin-rule", merged.getRuleId());
        assertEquals(List.of("CWE-321", "CWE-798"), merged.getCwes());
        assertEquals(Severity.HIGH, merged.getSeverity());
        assertEquals(Confidence.HIGH, merged.getConfidence());
        assertEquals(List.of("https://pmd.github.io"), merged.getReferences());
    }

    @Test
    void differentLinesOrCwesStaySeparate() {
        List<Finding> out = new TriageAgent().triage(List.of(
                code("builtin", "CWE-89", 10, Severity.CRITICAL, Confidence.HIGH),
                code("builtin", "CWE-89", 20, Severity.CRITICAL, Confidence.HIGH),
                code("builtin", "CWE-22", 10, Severity.HIGH, Confidence.HIGH)));
        assertEquals(3, out.size());
    }

    @Test
    void dependencyFindingsDedupeByPackageVersionAndCve() {
        DependencyRef log4j = new DependencyRef("org.apache.logging.log4j", "log4j-core", "2.14.1", null);
        Finding osv = Finding.dependency("osv", "GHSA-jfh8-c2jp-5v3q", log4j, "pom.xml");
        osv.addCve("CVE-2021-44228");
        Finding trivy = Finding.dependency("trivy", "CVE-2021-44228", log4j.withFixedVersion("2.15.0"), "pom.xml");
        trivy.addCve("CVE-2021-44228");

        List<Finding> out = new TriageAgent().triage(List.of(osv, trivy));

        assertEquals(1, out.size());
        assertEquals("2.15.0", out.get(0).getDependency().fixedVersion());
        assertEquals(Set.of("osv", "trivy"), out.get(0).getTools());
    }

    @Test
    void scoresRanksAndNumbers() {
        Finding low = code("builtin", "CWE-209", 5, Severity.LOW, Confidence.HIGH);
        Finding crit = code("builtin", "CWE-89", 9, Severity.CRITICAL, Confidence.HIGH);
        crit.setExploitability(new Exploitability(Exploitability.Verdict.LIKELY, "request input", "heuristic"));
        Finding medium = code("builtin", "CWE-327", 7, Severity.MEDIUM, Confidence.MEDIUM);
        medium.setExploitability(new Exploitability(Exploitability.Verdict.UNLIKELY, "constant", "heuristic"));

        List<Finding> out = new TriageAgent().triage(List.of(low, medium, crit));

        assertEquals(List.of("CWE-89", "CWE-209", "CWE-327"), out.stream().map(Finding::primaryCwe).toList());
        assertEquals(List.of("SP-001", "SP-002", "SP-003"), out.stream().map(Finding::getId).toList());
        assertEquals(10.0, out.get(0).getScore());
        assertEquals(2.0, out.get(1).getScore());
        assertEquals(1.9, out.get(2).getScore());
        out.forEach(f -> assertNotNull(f.getFingerprint()));
    }

    @Test
    void fingerprintIgnoresLineShifts() {
        Finding a = code("builtin", "CWE-89", 10, Severity.CRITICAL, Confidence.HIGH);
        Finding b = code("builtin", "CWE-89", 42, Severity.CRITICAL, Confidence.HIGH);
        b.setSnippet(a.getSnippet());
        assertEquals(a.computeFingerprint(), b.computeFingerprint());
    }
}
