package ca.carleton.secpipe.tools;

import ca.carleton.secpipe.core.DependencyRef;
import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Minimal client for the OSV.dev API (aggregates GitHub advisories, NVD CVEs and others). Responses
 * are cached under {@code ~/.secpipe/cache/osv} so repeat scans and {@code --offline} work.
 */
public class OsvClient {

    private static final int BATCH = 500;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final String baseUrl;
    private final Path cacheDir;
    private final boolean offline;

    public OsvClient(boolean offline) {
        this(baseUrl(), cacheDir(), offline);
    }

    public OsvClient(String baseUrl, Path cacheDir, boolean offline) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.cacheDir = cacheDir;
        this.offline = offline;
    }

    public static String baseUrl() {
        String env = System.getProperty("secpipe.osv.url", System.getenv("SECPIPE_OSV_URL"));
        return env == null || env.isBlank() ? "https://api.osv.dev" : env;
    }

    public static Path cacheDir() {
        String env = System.getProperty("secpipe.cache.dir", System.getenv("SECPIPE_CACHE_DIR"));
        Path base = env == null || env.isBlank() ? Path.of(System.getProperty("user.home"), ".secpipe", "cache") : Path.of(env);
        return base.resolve("osv");
    }

    public static boolean reachable() {
        try {
            HttpClient c = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            HttpResponse<Void> r = c.send(HttpRequest.newBuilder(URI.create(baseUrl() + "/v1/vulns/GHSA-jfh8-c2jp-5v3q"))
                    .timeout(Duration.ofSeconds(8)).GET().build(), HttpResponse.BodyHandlers.discarding());
            return r.statusCode() < 500;
        } catch (Exception e) {
            return false;
        }
    }

    /** Vulnerability ids affecting each dependency (keyed by coordinates). */
    public Map<DependencyRef, List<String>> query(List<DependencyRef> deps) throws ScanException {
        Map<DependencyRef, List<String>> out = new LinkedHashMap<>();
        List<DependencyRef> pending = new ArrayList<>();
        for (DependencyRef d : deps) {
            JsonNode cached = readCache("query", key(d));
            if (cached != null) {
                out.put(d, ids(cached));
            } else if (!offline) {
                pending.add(d);
            }
        }
        for (int start = 0; start < pending.size(); start += BATCH) {
            List<DependencyRef> chunk = pending.subList(start, Math.min(pending.size(), start + BATCH));
            ObjectNode body = Json.MAPPER.createObjectNode();
            ArrayNode queries = body.putArray("queries");
            for (DependencyRef d : chunk) {
                ObjectNode q = queries.addObject();
                q.putObject("package").put("ecosystem", "Maven").put("name", d.packageName());
                q.put("version", d.version());
            }
            JsonNode resp = post("/v1/querybatch", body);
            JsonNode results = resp.path("results");
            for (int i = 0; i < chunk.size(); i++) {
                JsonNode vulns = results.path(i).path("vulns");
                ArrayNode stored = Json.MAPPER.createArrayNode();
                vulns.forEach(v -> stored.add(v.path("id").asText()));
                writeCache("query", key(chunk.get(i)), stored);
                out.put(chunk.get(i), ids(stored));
            }
        }
        return out;
    }

    /** Full advisory records, fetched concurrently. Missing ones (offline, errors) are omitted. */
    public Map<String, JsonNode> details(List<String> ids) {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        Map<String, CompletableFuture<JsonNode>> inflight = new LinkedHashMap<>();
        for (String id : ids) {
            JsonNode cached = readCache("vulns", id);
            if (cached != null) {
                out.put(id, cached);
            } else if (!offline) {
                HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/v1/vulns/" + id))
                        .timeout(Duration.ofSeconds(30)).GET().build();
                inflight.put(id, http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).thenApply(r -> {
                    if (r.statusCode() != 200) return null;
                    try {
                        return Json.MAPPER.readTree(r.body());
                    } catch (IOException e) {
                        return null;
                    }
                }).exceptionally(e -> null));
            }
        }
        inflight.forEach((id, f) -> {
            JsonNode n = f.join();
            if (n != null) {
                writeCache("vulns", id, n);
                out.put(id, n);
            }
        });
        return out;
    }

    private JsonNode post(String path, JsonNode body) throws ScanException {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(60))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(Json.MAPPER.writeValueAsString(body)))
                    .build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                throw new ScanException("OSV API returned HTTP " + r.statusCode() + " for " + path);
            }
            return Json.MAPPER.readTree(r.body());
        } catch (IOException e) {
            throw new ScanException("cannot reach OSV.dev (" + baseUrl + "): " + e.getMessage()
                    + ". Check your connection or use --offline", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanException("interrupted while querying OSV", e);
        }
    }

    private static List<String> ids(JsonNode arr) {
        List<String> out = new ArrayList<>();
        arr.forEach(n -> out.add(n.asText()));
        return out;
    }

    private static String key(DependencyRef d) {
        return (d.packageName() + "@" + d.version()).replaceAll("[^A-Za-z0-9._@-]", "_");
    }

    private JsonNode readCache(String kind, String key) {
        Path f = cacheDir.resolve(kind).resolve(key + ".json");
        if (!Files.isRegularFile(f)) return null;
        try {
            if (kind.equals("query") && !offline
                    && Files.getLastModifiedTime(f).toMillis() < System.currentTimeMillis() - Duration.ofHours(24).toMillis()) {
                return null;
            }
            return Json.MAPPER.readTree(f.toFile());
        } catch (IOException e) {
            return null;
        }
    }

    private void writeCache(String kind, String key, JsonNode value) {
        try {
            Path dir = cacheDir.resolve(kind);
            Files.createDirectories(dir);
            Json.MAPPER.writeValue(dir.resolve(key.replaceAll("[^A-Za-z0-9._@-]", "_") + ".json").toFile(), value);
        } catch (IOException ignored) {
            // cache is an optimization only
        }
    }
}
