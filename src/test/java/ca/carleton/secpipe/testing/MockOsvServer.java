package ca.carleton.secpipe.testing;

import ca.carleton.secpipe.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A local stand-in for api.osv.dev so tests are deterministic and work offline. Serves the advisory
 * fixtures under {@code src/test/resources/osv/} and points secpipe at itself via system properties.
 */
public final class MockOsvServer implements AutoCloseable {

    private static final Map<String, List<String>> ADVISORIES = Map.of(
            "org.apache.logging.log4j:log4j-core", List.of("GHSA-jfh8-c2jp-5v3q"),
            "commons-collections:commons-collections", List.of("GHSA-fjq5-5j5f-mvxh"));

    private final HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();

    private MockOsvServer(Path cacheDir) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/querybatch", this::queryBatch);
        server.createContext("/v1/vulns/", this::vuln);
        server.start();
        System.setProperty("secpipe.osv.url", "http://127.0.0.1:" + server.getAddress().getPort());
        System.setProperty("secpipe.cache.dir", cacheDir.toString());
    }

    public static MockOsvServer start(Path cacheDir) throws IOException {
        return new MockOsvServer(cacheDir);
    }

    public int requestCount() {
        return requests.get();
    }

    private void queryBatch(HttpExchange ex) throws IOException {
        requests.incrementAndGet();
        JsonNode body = Json.MAPPER.readTree(ex.getRequestBody());
        ObjectNode resp = Json.MAPPER.createObjectNode();
        ArrayNode results = resp.putArray("results");
        for (JsonNode q : body.path("queries")) {
            ArrayNode vulns = results.addObject().putArray("vulns");
            ADVISORIES.getOrDefault(q.path("package").path("name").asText(), List.of())
                    .forEach(id -> vulns.addObject().put("id", id).put("modified", "2024-01-01T00:00:00Z"));
        }
        send(ex, 200, Json.MAPPER.writeValueAsBytes(resp));
    }

    private void vuln(HttpExchange ex) throws IOException {
        requests.incrementAndGet();
        String id = ex.getRequestURI().getPath().substring("/v1/vulns/".length());
        try (InputStream in = MockOsvServer.class.getResourceAsStream("/osv/" + id + ".json")) {
            if (in == null) {
                send(ex, 404, "{\"code\":5,\"message\":\"Bug not found.\"}".getBytes(StandardCharsets.UTF_8));
            } else {
                send(ex, 200, in.readAllBytes());
            }
        }
    }

    private static void send(HttpExchange ex, int status, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(body);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        System.clearProperty("secpipe.osv.url");
        System.clearProperty("secpipe.cache.dir");
    }
}
