package ca.carleton.secpipe.llm;

import ca.carleton.secpipe.util.Console;

public final class LlmClients {

    private LlmClients() {
    }

    public static LlmClient create(boolean aiRequested, Console console) {
        if (!aiRequested) return new NoopLlmClient();
        LlmSettings settings = LlmSettings.fromEnvironment();
        if (!settings.configured()) return new NoopLlmClient();
        return new OpenAiCompatibleClient(settings, console);
    }
}
