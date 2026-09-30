package ca.carleton.secpipe.tools.deps;

import ca.carleton.secpipe.core.DependencyRef;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DepsSupportTest {

    @Test
    void cvss3BaseScores() {
        assertEquals(10.0, Cvss3.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").orElseThrow());
        assertEquals(9.8, Cvss3.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").orElseThrow());
        assertEquals(5.9, Cvss3.baseScore("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N").orElseThrow());
        assertEquals(0.0, Cvss3.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").orElseThrow());
        assertTrue(Cvss3.baseScore("garbage").isEmpty());
        assertTrue(Cvss3.baseScore(null).isEmpty());
    }

    @Test
    void mavenVersionOrdering() {
        VersionComparator c = VersionComparator.INSTANCE;
        assertTrue(c.compare("2.14.1", "2.15.0") < 0);
        assertTrue(c.compare("1.2.10", "1.2.9") > 0);
        assertTrue(c.compare("2.0-rc1", "2.0") < 0);
        assertTrue(c.compare("2.0-SNAPSHOT", "2.0-beta") < 0);
        assertTrue(c.compare("3.2.2", "3.2.1") > 0);
        assertEquals(0, c.compare("1.0", "1.0"));
    }

    @Test
    void readsSamplePomWithPropertiesAndDependencyManagement() {
        Path pom = Path.of("samples/vulnerable-java-app/pom.xml");
        List<DependencyRef> deps = new DependencyResolver().fromManifests(List.of(pom));
        Map<String, String> versions = deps.stream()
                .collect(Collectors.toMap(DependencyRef::artifact, DependencyRef::version, (a, b) -> a));

        assertEquals("2.14.1", versions.get("log4j-core"));
        assertEquals("3.2.1", versions.get("commons-collections"));
        assertFalse(versions.containsKey("junit"), "test-scoped dependencies are excluded");
        deps.forEach(d -> assertFalse(d.version().contains("${"), "unresolved property in " + d));
    }
}
