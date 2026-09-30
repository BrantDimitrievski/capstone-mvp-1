package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.ScanResult;
import ca.carleton.secpipe.util.Json;

import java.io.IOException;
import java.nio.file.Path;

/** Full machine-readable result; also the baseline input for {@code secpipe verify}. */
public class JsonReporter implements ReportWriter {

    @Override
    public String format() {
        return "json";
    }

    @Override
    public Path write(ScanResult result, Path outDir) throws IOException {
        Path file = outDir.resolve("report.json");
        Json.MAPPER.writeValue(file.toFile(), result);
        return file;
    }
}
