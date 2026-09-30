package ca.carleton.secpipe.agents;

import ca.carleton.secpipe.core.ScanContext;
import ca.carleton.secpipe.core.SecPipeException;

/** One specialized step of the pipeline. Agents read and enrich the shared {@link PipelineState}. */
public interface Agent {

    String name();

    /** One-line description of the agent's responsibility, shown in verbose output and the README. */
    String role();

    void run(ScanContext ctx, PipelineState state) throws SecPipeException;
}
