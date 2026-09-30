package ca.carleton.secpipe.tools;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ProjectProfile;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.Severity;
import net.sourceforge.pmd.PMDConfiguration;
import net.sourceforge.pmd.PmdAnalysis;
import net.sourceforge.pmd.reporting.Report;
import net.sourceforge.pmd.reporting.RuleViolation;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** PMD 7 embedded as a library, restricted to its security-relevant rules. */
public class PmdAdapter implements ScannerAdapter {

    private record RuleInfo(String cwe, Severity severity, Confidence confidence, String title) {
    }

    private static final Map<String, RuleInfo> RULES = Map.of(
            "HardCodedCryptoKey", new RuleInfo("CWE-321", Severity.HIGH, Confidence.HIGH, "Hard-coded cryptographic key"),
            "InsecureCryptoIv", new RuleInfo("CWE-329", Severity.MEDIUM, Confidence.HIGH, "Predictable initialization vector"),
            "AvoidUsingHardCodedIP", new RuleInfo("CWE-547", Severity.LOW, Confidence.MEDIUM, "Hard-coded IP address"),
            "AvoidPrintStackTrace", new RuleInfo("CWE-209", Severity.LOW, Confidence.LOW, "Stack trace printed to output"));

    @Override
    public String id() {
        return "pmd";
    }

    @Override
    public String displayName() {
        return "PMD 7 (security rules)";
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

    @Override
    public List<Finding> run(ScanContext ctx) throws ScanException {
        PMDConfiguration config = new PMDConfiguration();
        config.addRuleSet("pmd/secpipe-security.xml");
        config.setIgnoreIncrementalAnalysis(true);
        config.setThreads(Math.max(1, Runtime.getRuntime().availableProcessors()));

        List<Finding> out = new ArrayList<>();
        try (PmdAnalysis pmd = PmdAnalysis.create(config)) {
            for (Path file : ctx.profile().sourceFiles()) pmd.files().addFile(file);
            Report report = pmd.performAnalysisAndCollectReport();
            for (Report.ConfigurationError err : report.getConfigurationErrors()) {
                ctx.console().debug("pmd config: " + err.issue());
            }
            for (Report.ProcessingError err : report.getProcessingErrors()) {
                ctx.console().debug("pmd could not analyze " + err.getFileId().getOriginalPath() + ": " + err.getMsg());
            }
            for (RuleViolation v : report.getViolations()) {
                String ruleName = v.getRule().getName();
                RuleInfo info = RULES.getOrDefault(ruleName,
                        new RuleInfo(null, Severity.LOW, Confidence.LOW, ruleName));
                String rel = ctx.profile().relativize(Path.of(v.getFileId().getAbsolutePath()));
                Finding f = Finding.code(id(), "PMD:" + ruleName, rel, v.getBeginLine());
                f.addCwe(info.cwe());
                f.setSeverity(info.severity());
                f.setConfidence(info.confidence());
                f.setTitle(info.title());
                f.setMessage(v.getDescription());
                if (v.getRule().getExternalInfoUrl() != null) f.addReference(v.getRule().getExternalInfoUrl());
                out.add(f);
            }
        } catch (RuntimeException e) {
            throw new ScanException("PMD failed: " + e.getMessage(), e);
        }
        return out;
    }
}
