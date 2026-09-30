package ca.carleton.secpipe.llm;

/**
 * LLM configuration from the environment. Any OpenAI-compatible Chat Completions endpoint works
 * (OpenAI, Azure OpenAI proxies, Ollama at http://localhost:11434/v1, LM Studio, vLLM, ...).
 */
public record LlmSettings(String baseUrl, String apiKey, String model, boolean configured) {

    public static LlmSettings fromEnvironment() {
        String url = env("SECPIPE_LLM_URL");
        String key = env("SECPIPE_LLM_KEY");
        if (key == null) key = env("OPENAI_API_KEY");
        String model = env("SECPIPE_LLM_MODEL");
        boolean configured = key != null || url != null;
        if (url == null) url = "https://api.openai.com/v1";
        if (model == null) model = url.contains("11434") ? "llama3.1" : "gpt-4o-mini";
        return new LlmSettings(url.endsWith("/") ? url.substring(0, url.length() - 1) : url, key, model, configured);
    }

    private static String env(String name) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? null : v.trim();
    }
}
