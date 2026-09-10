// Fixtures for java-reflection-injection.
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class ReflectionInjection {
    Map<String, Class<?>> allowlist;

    Class<?> tainted(HttpServletRequest request) throws Exception {
        // ruleid: java-reflection-injection
        return Class.forName(request.getParameter("c"));
    }

    // String.valueOf is a conversion, not an allowlist lookup.
    Class<?> taintedThroughValueOf(HttpServletRequest request) throws Exception {
        // ruleid: java-reflection-injection
        return Class.forName(String.valueOf(request.getParameter("c")));
    }

    // Resolving through an allowlist removes attacker control.
    Class<?> allowlisted(HttpServletRequest request) throws Exception {
        // ok: java-reflection-injection
        return allowlist.get(request.getParameter("c"));
    }

    // Constant class names and ordinary reflection are not injection.
    Class<?> constant() throws Exception {
        // ok: java-reflection-injection
        return Class.forName("sun.misc.Cleaner");
    }

    Object proxyDispatch(java.lang.reflect.Method method, Object target, Object[] args) throws Exception {
        // ok: java-reflection-injection
        return method.invoke(target, args);
    }

    // A classpath resource stream is not request input.
    Object scriptFromResource(javax.script.ScriptEngine engine, org.springframework.core.io.Resource resource) throws Exception {
        // ok: java-reflection-injection
        return engine.eval(new java.io.InputStreamReader(resource.getInputStream()));
    }
}
