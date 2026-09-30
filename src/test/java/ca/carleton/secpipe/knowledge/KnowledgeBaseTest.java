package ca.carleton.secpipe.knowledge;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KnowledgeBaseTest {

    private final KnowledgeBase kb = KnowledgeBase.load();

    @Test
    void normalizesCweSpellings() {
        assertEquals(Optional.of("CWE-89"), KnowledgeBase.normalizeCwe("CWE-89: Improper Neutralization of ..."));
        assertEquals(Optional.of("CWE-79"), KnowledgeBase.normalizeCwe("cwe_79"));
        assertEquals(Optional.of("CWE-22"), KnowledgeBase.normalizeCwe("CWE 22"));
        assertTrue(KnowledgeBase.normalizeCwe("not a cwe").isEmpty());
        assertTrue(KnowledgeBase.normalizeCwe(null).isEmpty());
    }

    @Test
    void mapsCwesToOwaspTop10() {
        assertEquals("A03:2021", kb.owaspFor("CWE-89").orElseThrow().id());
        assertEquals("A03:2021", kb.owaspFor("CWE-78").orElseThrow().id());
        assertEquals("A01:2021", kb.owaspFor("CWE-22").orElseThrow().id());
        assertEquals("A07:2021", kb.owaspFor("CWE-798").orElseThrow().id());
        assertEquals("A02:2021", kb.owaspFor("CWE-327").orElseThrow().id());
        assertEquals("A08:2021", kb.owaspFor("CWE-502").orElseThrow().id());
        assertEquals("A06:2021", kb.vulnerableComponents().id());
        assertEquals(10, kb.owaspCategories().size());
    }

    @Test
    void everySeededCweHasGuidance() {
        for (String cwe : new String[]{"CWE-89", "CWE-22", "CWE-78", "CWE-798", "CWE-321", "CWE-327", "CWE-328", "CWE-502", "CWE-209"}) {
            KnowledgeBase.CweEntry e = kb.cwe(cwe).orElseThrow(() -> new AssertionError("missing " + cwe));
            assertFalse(e.name().isBlank(), cwe);
            assertFalse(e.fix().isBlank(), cwe);
            assertTrue(e.url().contains("cwe.mitre.org"), cwe);
        }
        assertTrue(kb.cweCount() >= 30);
    }
}
