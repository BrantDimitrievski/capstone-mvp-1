package ca.carleton.secpipe.core;

import ca.carleton.secpipe.knowledge.KnowledgeBase;
import ca.carleton.secpipe.llm.LlmClient;
import ca.carleton.secpipe.util.Console;
import com.github.javaparser.ast.CompilationUnit;

import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Shared, read-mostly state handed to every agent and adapter during one scan. */
public class ScanContext {

    private final ScanConfig config;
    private final ProjectProfile profile;
    private final CodeMap codeMap;
    private final Map<Path, CompilationUnit> parsedSources;
    private final KnowledgeBase knowledge;
    private final LlmClient llm;
    private final Console console;
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    public ScanContext(ScanConfig config, ProjectProfile profile, CodeMap codeMap,
                       Map<Path, CompilationUnit> parsedSources, KnowledgeBase knowledge,
                       LlmClient llm, Console console) {
        this.config = config;
        this.profile = profile;
        this.codeMap = codeMap;
        this.parsedSources = parsedSources;
        this.knowledge = knowledge;
        this.llm = llm;
        this.console = console;
    }

    public ScanConfig config() { return config; }
    public ProjectProfile profile() { return profile; }
    public CodeMap codeMap() { return codeMap; }
    public Map<Path, CompilationUnit> parsedSources() { return parsedSources; }
    public KnowledgeBase knowledge() { return knowledge; }
    public LlmClient llm() { return llm; }
    public Console console() { return console; }
    public Path root() { return profile.root(); }

    public void put(String key, Object value) {
        attributes.put(key, value);
    }

    @SuppressWarnings("unchecked")
    public <T> T get(String key) {
        return (T) attributes.get(key);
    }
}
