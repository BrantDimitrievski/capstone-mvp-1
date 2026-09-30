package ca.carleton.secpipe.report;

import ca.carleton.secpipe.core.ScanResult;

import java.io.IOException;
import java.nio.file.Path;

/** Writes one report format. Add a class and register it in {@link Reports#ALL} to support a new format. */
public interface ReportWriter {

    /** Format id used by --format, e.g. "html". */
    String format();

    Path write(ScanResult result, Path outDir) throws IOException;
}
