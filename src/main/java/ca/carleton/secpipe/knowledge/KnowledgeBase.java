package ca.carleton.secpipe.knowledge;

import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Offline CWE and OWASP Top 10 (2021) catalogs bundled with the tool. */
public class KnowledgeBase {

    public record CweEntry(String id, String name, String description, String fix, String example) {
        public String url() {
            return "https://cwe.mitre.org/data/definitions/" + id.substring(4) + ".html";
        }
    }

    public record OwaspCategory(String id, String name, String url) {
        public String label() {
            return id + " - " + name;
        }
    }

    private static final Pattern CWE_ID = Pattern.compile("(?i)CWE[-_ ]?(\\d+)");
    private static volatile KnowledgeBase instance;

    private final Map<String, CweEntry> cwes = new LinkedHashMap<>();
    private final Map<String, OwaspCategory> owaspByCwe = new HashMap<>();
    private final Map<String, OwaspCategory> owaspById = new LinkedHashMap<>();

    public static KnowledgeBase load() {
        if (instance == null) {
            synchronized (KnowledgeBase.class) {
                if (instance == null) instance = new KnowledgeBase();
            }
        }
        return instance;
    }

    private KnowledgeBase() {
        JsonNode cweRoot = read("/knowledge/cwe-subset.json").path("cwes");
        cweRoot.fields().forEachRemaining(e -> {
            JsonNode n = e.getValue();
            cwes.put(e.getKey(), new CweEntry(e.getKey(), n.path("name").asText(), n.path("description").asText(),
                    n.path("fix").asText(), n.path("example").asText(null)));
        });
        for (JsonNode c : read("/knowledge/owasp-top10-2021.json").path("categories")) {
            OwaspCategory cat = new OwaspCategory(c.path("id").asText(), c.path("name").asText(), c.path("url").asText());
            owaspById.put(cat.id(), cat);
            c.path("cwes").forEach(cwe -> owaspByCwe.putIfAbsent(cwe.asText(), cat));
        }
    }

    private static JsonNode read(String resource) {
        try (InputStream in = KnowledgeBase.class.getResourceAsStream(resource)) {
            if (in == null) throw new IllegalStateException("missing bundled resource " + resource);
            return Json.MAPPER.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Normalizes "CWE-89: Improper Neutralization..." or "cwe_89" to "CWE-89". */
    public static Optional<String> normalizeCwe(String raw) {
        if (raw == null) return Optional.empty();
        Matcher m = CWE_ID.matcher(raw);
        return m.find() ? Optional.of("CWE-" + m.group(1)) : Optional.empty();
    }

    public Optional<CweEntry> cwe(String id) {
        return Optional.ofNullable(cwes.get(id));
    }

    public Optional<OwaspCategory> owaspFor(String cwe) {
        return Optional.ofNullable(owaspByCwe.get(cwe));
    }

    public OwaspCategory vulnerableComponents() {
        return owaspById.get("A06:2021");
    }

    public Map<String, OwaspCategory> owaspCategories() {
        return owaspById;
    }

    public int cweCount() {
        return cwes.size();
    }
}
