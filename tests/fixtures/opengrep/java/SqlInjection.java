// Fixtures for java-sql-injection.
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

public class SqlInjection {
    private JdbcTemplate jdbcTemplate;

    void concatenated(Statement stmt, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        // ruleid: java-sql-injection
        stmt.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");
    }

    // A concatenated query handed to prepareStatement() and run with a
    // no-argument execute() is reported at the preparation.
    void preparedFromConcat(Connection conn, HttpServletRequest request) throws Exception {
        String sql = "SELECT * FROM t WHERE id = '" + request.getParameter("id") + "'";
        // ruleid: java-sql-injection
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.execute();
    }

    void templateConcat(HttpServletRequest request) {
        String id = request.getParameter("id");
        // ruleid: java-sql-injection
        jdbcTemplate.update("UPDATE t SET x = '" + id + "'");
    }

    // Bind parameters are the remediation, not an injection. Only the SQL
    // string argument is the sink.
    void templateParameterized(HttpServletRequest request) {
        String id = request.getParameter("id");
        // ok: java-sql-injection
        jdbcTemplate.update("UPDATE t SET x = ?", id);
        // ok: java-sql-injection
        jdbcTemplate.queryForObject("SELECT c FROM t WHERE id = ?", Integer.class, id);
    }

    void preparedParameterized(Connection conn, HttpServletRequest request) throws Exception {
        // ok: java-sql-injection
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");
        ps.setString(1, request.getParameter("id"));
        ps.execute();
    }

    // update() on a digest is not a query, whether the receiver is a declared
    // variable or the factory call is chained inline.
    void digests(HttpServletRequest request) throws Exception {
        String input = request.getParameter("p");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // ok: java-sql-injection
        md.update(input.getBytes());
        // ok: java-sql-injection
        MessageDigest.getInstance("SHA-256").update(input.getBytes());
    }
}
