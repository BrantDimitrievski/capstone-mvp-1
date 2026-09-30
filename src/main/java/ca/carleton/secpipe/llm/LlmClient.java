package ca.carleton.secpipe.llm;

import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Optional;

/** Chat-completion abstraction used by agents. Every caller must work when this returns empty. */
public interface LlmClient {

    boolean enabled();

    String model();

    Optional<String> complete(String system, String user);

    /** Completes and parses the first JSON object in the reply. */
    default Optional<JsonNode> completeJson(String system, String user) {
        return complete(system, user).flatMap(text -> {
            int start = text.indexOf('{');
            int end = text.lastIndexOf('}');
            if (start < 0 || end <= start) return Optional.empty();
            try {
                return Optional.of(Json.MAPPER.readTree(text.substring(start, end + 1)));
            } catch (Exception e) {
                return Optional.empty();
            }
        });
    }

    /** Extracts the body of the first fenced code block, or the whole text if there is none. */
    static String stripCodeFence(String text) {
        int fence = text.indexOf("```");
        if (fence < 0) return text.strip();
        int bodyStart = text.indexOf('\n', fence);
        int close = text.indexOf("```", bodyStart + 1);
        if (bodyStart < 0 || close < 0) return text.strip();
        return text.substring(bodyStart + 1, close).strip();
    }
}
