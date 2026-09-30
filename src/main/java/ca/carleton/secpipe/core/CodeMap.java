package ca.carleton.secpipe.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lightweight structural map of the codebase built by the orchestrator: classes, methods, HTTP
 * endpoints and which methods read untrusted request input. Agents use it for reachability hints.
 */
public class CodeMap {

    public record MethodInfo(
            String file,
            String className,
            String name,
            int beginLine,
            int endLine,
            boolean endpoint,
            String route,
            boolean readsRequestInput) {

        public String qualifiedName() {
            return className + "." + name;
        }
    }

    private final Map<String, List<MethodInfo>> methodsByFile = new ConcurrentHashMap<>();
    private volatile int classCount;

    public void addMethods(String file, List<MethodInfo> methods) {
        methodsByFile.put(file, List.copyOf(methods));
    }

    public void setClassCount(int classCount) {
        this.classCount = classCount;
    }

    public int classCount() {
        return classCount;
    }

    public int methodCount() {
        return methodsByFile.values().stream().mapToInt(List::size).sum();
    }

    /** Innermost method whose line range contains {@code line}. */
    public Optional<MethodInfo> methodAt(String file, int line) {
        List<MethodInfo> methods = methodsByFile.getOrDefault(file, List.of());
        MethodInfo best = null;
        for (MethodInfo m : methods) {
            if (line >= m.beginLine() && line <= m.endLine()) {
                if (best == null || (m.endLine() - m.beginLine()) < (best.endLine() - best.beginLine())) {
                    best = m;
                }
            }
        }
        return Optional.ofNullable(best);
    }

    public List<MethodInfo> methodsIn(String file) {
        return methodsByFile.getOrDefault(file, List.of());
    }

    public List<MethodInfo> endpoints() {
        List<MethodInfo> out = new ArrayList<>();
        methodsByFile.values().forEach(ms -> ms.stream().filter(MethodInfo::endpoint).forEach(out::add));
        out.sort((a, b) -> a.qualifiedName().compareTo(b.qualifiedName()));
        return out;
    }

    /** True if some method in the file is an HTTP endpoint or reads request input. */
    public boolean fileHandlesRequests(String file) {
        return methodsIn(file).stream().anyMatch(m -> m.endpoint() || m.readsRequestInput());
    }
}
