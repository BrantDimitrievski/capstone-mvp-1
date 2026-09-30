package ca.carleton.secpipe.tools.builtin;

/** One built-in detection rule. Rules only look at a single file (localized issues). */
public interface JavaRule {

    String id();

    /** CWE the rule is primarily about, e.g. "CWE-89". */
    String cwe();

    void check(RuleContext ctx);
}
