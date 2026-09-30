package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;

/** CWE-502: deserializing untrusted data with gadget-prone APIs. */
public class DeserializationRule implements JavaRule {

    @Override
    public String id() {
        return "SP-JAVA-DESER";
    }

    @Override
    public String cwe() {
        return "CWE-502";
    }

    @Override
    public void check(RuleContext ctx) {
        for (ObjectCreationExpr oc : ctx.cu().findAll(ObjectCreationExpr.class)) {
            String type = oc.getType().getNameAsString();
            if (type.equals("ObjectInputStream")) {
                TaintTracker t = ctx.taintFor(oc);
                if (t.bodyContains("setObjectInputFilter") || t.bodyContains("ObjectInputFilter")) continue;
                TaintLevel level = oc.getArguments().stream().map(t::level).reduce(TaintLevel.NONE, TaintLevel::max);
                boolean reads = t.bodyContains("readObject") || t.bodyContains("readUnshared");
                Confidence confidence = level == TaintLevel.REQUEST ? Confidence.HIGH : reads ? Confidence.MEDIUM : Confidence.LOW;
                ctx.report(oc, id(), cwe(), level == TaintLevel.REQUEST ? Severity.CRITICAL : Severity.HIGH, confidence,
                        "Deserialization of untrusted data",
                        "ObjectInputStream deserializes arbitrary classes" + (level == TaintLevel.REQUEST ? " from the HTTP request" : "")
                                + " without an ObjectInputFilter. Crafted input can trigger gadget chains and remote code execution. "
                                + "Use JSON with explicit types, or set an allow-list ObjectInputFilter.");
            } else if (type.equals("XMLDecoder")) {
                ctx.report(oc, id(), cwe(), Severity.HIGH, Confidence.MEDIUM, "Deserialization of untrusted data",
                        "java.beans.XMLDecoder can instantiate arbitrary classes and call methods from XML input. Do not use it on untrusted data.");
            }
        }
        for (MethodCallExpr mc : ctx.cu().findAll(MethodCallExpr.class)) {
            String name = mc.getNameAsString();
            if (name.equals("enableDefaultTyping") || (name.equals("activateDefaultTyping") && mc.toString().contains("LaissezFaire"))) {
                ctx.report(mc, id(), cwe(), Severity.HIGH, Confidence.MEDIUM, "Unsafe polymorphic deserialization",
                        "Jackson default typing lets JSON choose which classes to instantiate. Remove it or use a strict PolymorphicTypeValidator.");
            } else if (name.equals("fromXML") && mc.getScope().map(s -> s.toString().toLowerCase().contains("xstream")).orElse(false)) {
                ctx.report(mc, id(), cwe(), Severity.HIGH, Confidence.MEDIUM, "Deserialization of untrusted data",
                        "XStream.fromXML() on untrusted input can instantiate arbitrary types. Configure XStream's security framework with an allow-list.");
            }
        }
    }
}
