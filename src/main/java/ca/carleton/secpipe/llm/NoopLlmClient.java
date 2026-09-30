package ca.carleton.secpipe.llm;

import java.util.Optional;

/** Used with --no-ai or when no LLM is configured; agents fall back to deterministic logic. */
public class NoopLlmClient implements LlmClient {

    @Override
    public boolean enabled() {
        return false;
    }

    @Override
    public String model() {
        return "none";
    }

    @Override
    public Optional<String> complete(String system, String user) {
        return Optional.empty();
    }
}
