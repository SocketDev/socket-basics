// Fixtures for java-ldap-injection.
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class LdapInjection {
    Object tainted(DirContext ctx, HttpServletRequest request) throws Exception {
        String user = request.getParameter("u");
        // ruleid: java-ldap-injection
        return ctx.search("ou=people", "(uid=" + user + ")", new SearchControls());
    }

    // Servlet code commonly declares the context fully qualified.
    Object taintedQualified(javax.naming.directory.InitialDirContext idc,
                            HttpServletRequest request) throws Exception {
        String user = request.getParameter("u");
        // ruleid: java-ldap-injection
        return idc.search("ou=people", "(uid=" + user + ")", new SearchControls());
    }

    Object escaped(DirContext ctx, HttpServletRequest request) throws Exception {
        String user = org.springframework.ldap.support.LdapEncoder.filterEncode(request.getParameter("u"));
        // ok: java-ldap-injection
        return ctx.search("ou=people", "(uid=" + user + ")", new SearchControls());
    }

    // A Lucene search is not an LDAP search. An untyped $CTX.search() sink
    // turned this into a CRITICAL finding.
    Object luceneSearch(org.apache.lucene.search.IndexSearcher searcher,
                        org.apache.lucene.search.Query query,
                        HttpServletRequest request) throws Exception {
        String text = request.getParameter("q");
        // ok: java-ldap-injection
        return searcher.search(query, Integer.parseInt(text));
    }
}
