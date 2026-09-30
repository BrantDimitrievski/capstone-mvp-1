package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.Finding;
import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.ToolRun;
import ca.carleton.secpipe.tools.ScannerAdapter;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Runs adapters concurrently and isolates failures so one broken tool never aborts the scan. */
final class AdapterRunner {

    static final ExecutorService POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "secpipe-worker");
        t.setDaemon(true);
        return t;
    });

    private AdapterRunner() {
    }

    static void runAll(ScanContext ctx, PipelineState state, List<ScannerAdapter> adapters) {
        List<CompletableFuture<Void>> futures = adapters.stream()
                .map(a -> CompletableFuture.runAsync(() -> runOne(ctx, state, a), POOL))
                .toList();
        futures.forEach(CompletableFuture::join);
    }

    private static void runOne(ScanContext ctx, PipelineState state, ScannerAdapter adapter) {
        long start = System.nanoTime();
        ctx.console().info("running " + adapter.displayName() + "...");
        try {
            List<Finding> found = adapter.run(ctx);
            long ms = (System.nanoTime() - start) / 1_000_000;
            state.findings().addAll(found);
            String note = ctx.get("note:" + adapter.id());
            String message = found.size() + " finding(s)" + (note == null ? "" : "; " + note);
            state.toolRuns().add(new ToolRun(adapter.id(), adapter.category(), ToolRun.Status.OK, message, found.size(), ms));
            ctx.console().info(adapter.id() + ": " + message + " in " + ms + " ms");
        } catch (Exception e) {
            long ms = (System.nanoTime() - start) / 1_000_000;
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            state.toolRuns().add(new ToolRun(adapter.id(), adapter.category(), ToolRun.Status.FAILED, msg, 0, ms));
            ctx.console().warn(adapter.id() + " failed: " + msg);
            if (ctx.console().isVerbose()) e.printStackTrace();
        }
    }
}
