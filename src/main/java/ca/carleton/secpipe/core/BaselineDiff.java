package ca.carleton.secpipe.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Compares a baseline scan with a re-scan after remediation. */
public record BaselineDiff(List<Finding> fixed, List<Finding> stillPresent, List<Finding> introduced) {

    public static BaselineDiff compare(ScanResult baseline, ScanResult current) {
        Map<String, Finding> before = index(baseline.getFindings());
        Map<String, Finding> after = index(current.getFindings());
        List<Finding> fixed = new ArrayList<>();
        List<Finding> still = new ArrayList<>();
        List<Finding> introduced = new ArrayList<>();
        before.forEach((fp, f) -> (after.containsKey(fp) ? still : fixed).add(after.getOrDefault(fp, f)));
        after.forEach((fp, f) -> {
            if (!before.containsKey(fp)) introduced.add(f);
        });
        return new BaselineDiff(fixed, still, introduced);
    }

    private static Map<String, Finding> index(List<Finding> findings) {
        return findings.stream().collect(Collectors.toMap(
                f -> f.getFingerprint() != null ? f.getFingerprint() : f.computeFingerprint(),
                Function.identity(),
                (a, b) -> a,
                java.util.LinkedHashMap::new));
    }

    public boolean passes(Severity failOn) {
        if (failOn == null) return true;
        return stillPresent.stream().noneMatch(f -> f.getSeverity().atLeast(failOn))
                && introduced.stream().noneMatch(f -> f.getSeverity().atLeast(failOn));
    }
}
