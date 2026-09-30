package ca.carleton.secpipe.tools;

import ca.carleton.secpipe.core.Category;
import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ProjectProfile;
import ca.carleton.secpipe.core.ScanContext;

import java.util.List;

/**
 * Contract for plugging an analyzer into the pipeline (NFR4). Implement this, then register the
 * adapter in {@link ToolRegistry#defaults()}.
 */
public interface ScannerAdapter {

    /** Short, stable, lowercase id used in --tools/--exclude-tools and in reports. */
    String id();

    /** Human-readable name, e.g. "PMD 7 (security rules)". */
    String displayName();

    Category category();

    /** Embedded analyzers return true; external ones check that their binary is on PATH. */
    boolean isAvailable();

    /** Shown when {@link #isAvailable()} is false, e.g. how to install the tool. */
    default String unavailableReason() {
        return "not installed";
    }

    /** Where the analyzer comes from, shown by {@code secpipe doctor}: "embedded" or the binary path. */
    default String detail() {
        return "embedded";
    }

    boolean supports(ProjectProfile profile);

    List<Finding> run(ScanContext ctx) throws ScanException;
}
