package ca.carleton.secpipe.llm;

import ca.carleton.secpipe.util.Console;
import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Client for any OpenAI-compatible {@code /chat/completions} endpoint. */
public class OpenAiCompatibleClient implements LlmClient {

    private static final int MAX_CONSECUTIVE_FAILURES = 3;

    private final LlmSettings settings;
    private final Console console;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final AtomicInteger failures = new AtomicInteger();
    private final AtomicBoolean warned = new AtomicBoolean();

    public OpenAiCompatibleClient(LlmSettings settings, Console console) {
        this.settings = settings;
        this.console = console;
    }

    @Override
    public boolean enabled() {
        return failures.get() < MAX_CONSECUTIVE_FAILURES;
    }

    @Override
    public String model() {
        return settings.model();
    }

    @Override
    public Optional<String> complete(String system, String user) {
        if (!enabled()) return Optional.empty();
        try {
            ObjectNode body = Json.MAPPER.createObjectNode();
            body.put("model", settings.model());
            body.put("temperature", 0.1);
            ArrayNode messages = body.putArray("messages");
            messages.addObject().put("role", "system").put("content", system);
            messages.addObject().put("role", "user").put("content", user);

            HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(settings.baseUrl() + "/chat/completions"))
                    .timeout(Duration.ofSeconds(90))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(Json.MAPPER.writeValueAsString(body)));
            if (settings.apiKey() != null) req.header("Authorization", "Bearer " + settings.apiKey());

            HttpResponse<String> resp = http.send(req.build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                fail("LLM endpoint returned HTTP " + resp.statusCode() + " (" + summarize(resp.body()) + ")");
                return Optional.empty();
            }
            JsonNode json = Json.MAPPER.readTree(resp.body());
            String content = json.path("choices").path(0).path("message").path("content").asText("");
            failures.set(0);
            return content.isBlank() ? Optional.empty() : Optional.of(content);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            fail("LLM request failed: " + e.getMessage());
            return Optional.empty();
        }
    }

    private void fail(String message) {
        int n = failures.incrementAndGet();
        if (warned.compareAndSet(false, true)) {
            console.warn(message + "; continuing with deterministic analysis where needed.");
        }
        if (n == MAX_CONSECUTIVE_FAILURES) console.warn("LLM disabled for the rest of this scan after repeated failures.");
    }

    private static String summarize(String body) {
        if (body == null) return "";
        String s = body.replaceAll("\\s+", " ").strip();
        return s.length() > 160 ? s.substring(0, 157) + "..." : s;
    }
}
