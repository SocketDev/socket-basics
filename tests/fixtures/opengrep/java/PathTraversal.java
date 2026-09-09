// Fixtures for java-path-traversal.
import java.io.*;
import java.nio.file.*;
import java.util.zip.*;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    static final Path BASE = Paths.get("/var/data");

    void unvalidated(HttpServletRequest request) throws Exception {
        String name = request.getParameter("f");
        // ruleid: java-path-traversal
        Files.newInputStream(BASE.resolve(name));
    }

    void qualifiedSink(HttpServletRequest request) throws Exception {
        String name = request.getParameter("f");
        // ruleid: java-path-traversal
        new java.io.FileInputStream("/var/data/" + name);
    }

    // Zip Slip: the archive entry name is attacker controlled.
    void zipSlip(File zipFile, File dir) throws Exception {
        ZipFile zip = new ZipFile(zipFile);
        ZipEntry e = zip.entries().nextElement();
        // ruleid: java-path-traversal
        File f = new File(dir, e.getName());
        Files.copy(zip.getInputStream(e), f.toPath());
    }

    // A containment check must suppress the finding at the later sink.
    void contained(HttpServletRequest request) throws Exception {
        String name = request.getParameter("f");
        Path p = BASE.resolve(name).normalize();
        if (!p.startsWith(BASE)) {
            throw new IOException("outside base");
        }
        // ok: java-path-traversal
        Files.newInputStream(p);
    }

    // Reducing to a bare filename removes the traversal.
    void basename(HttpServletRequest request) throws Exception {
        String name = org.apache.commons.io.FilenameUtils.getName(request.getParameter("f"));
        // ok: java-path-traversal
        Files.newInputStream(BASE.resolve(name));
    }
}
