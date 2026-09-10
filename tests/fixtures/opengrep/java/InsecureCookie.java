// Fixtures for java-insecure-cookie.
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class InsecureCookie {
    private Cookie field;

    // A hardened cookie must not exonerate an unhardened neighbour.
    void neighbour(HttpServletResponse resp) {
        Cookie a = new Cookie("a", "1");
        // ruleid: java-insecure-cookie
        Cookie b = new Cookie("b", "2");
        a.setSecure(true);
        resp.addCookie(a);
        resp.addCookie(b);
    }

    void hardened(HttpServletResponse resp) {
        // ok: java-insecure-cookie
        Cookie c = new Cookie("c", "3");
        c.setSecure(true);
        resp.addCookie(c);
    }

    // Hardened through a field.
    void viaField(HttpServletResponse resp) {
        // ok: java-insecure-cookie
        this.field = new Cookie("d", "4");
        this.field.setSecure(true);
        resp.addCookie(this.field);
    }

    // Never assigned to a variable at all.
    void inline(HttpServletResponse resp) {
        // ruleid: java-insecure-cookie
        resp.addCookie(new Cookie("e", "5"));
    }
}
