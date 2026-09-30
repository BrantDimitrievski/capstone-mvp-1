package ca.carleton.secpipe.core;

/** Outcome of running one analyzer, shown in the report so users can see what actually ran. */
public record ToolRun(String tool, Category category, Status status, String message, int findings, long durationMs) {

    public enum Status { OK, SKIPPED, FAILED }

    public static ToolRun skipped(String tool, Category category, String reason) {
        return new ToolRun(tool, category, Status.SKIPPED, reason, 0, 0);
    }
}
