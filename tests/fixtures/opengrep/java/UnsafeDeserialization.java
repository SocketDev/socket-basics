// Fixtures for java-unsafe-deserialization.
import java.io.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

public class UnsafeDeserialization implements Serializable {
    // Field-held instances are the common real-world shape.
    private final Yaml safeYaml = new Yaml(new SafeConstructor(new LoaderOptions()));
    private final Yaml unsafeYaml = new Yaml();

    Object fromStream(ObjectInputStream ois) throws Exception {
        // ruleid: java-unsafe-deserialization
        return ois.readObject();
    }

    Object inline(InputStream in) throws Exception {
        // ruleid: java-unsafe-deserialization
        return new ObjectInputStream(in).readObject();
    }

    Object yamlUnsafe(String s) {
        // ruleid: java-unsafe-deserialization
        return new Yaml().load(s);
    }

    Object yamlUnsafeField(String s) {
        // ruleid: java-unsafe-deserialization
        return unsafeYaml.load(s);
    }

    // loadAs and loadAll deserialize the same way load does.
    Object yamlUnsafeLoadAs(String s) {
        // ruleid: java-unsafe-deserialization
        return new Yaml().loadAs(s, Object.class);
    }

    // The rule's own fix text recommends SafeConstructor, so it must not fire.
    Object yamlSafeInline(String s) {
        // ok: java-unsafe-deserialization
        return new Yaml(new SafeConstructor()).load(s);
    }

    Object yamlSafeVariable(String s) {
        Yaml y = new Yaml(new SafeConstructor());
        // ok: java-unsafe-deserialization
        return y.load(s);
    }

    Object yamlSafeField(String s) {
        // ok: java-unsafe-deserialization
        return safeYaml.load(s);
    }

    // SnakeYAML 2.0 removed the no-arg SafeConstructor.
    Object yamlSafeLoaderOptions(String s) {
        // ok: java-unsafe-deserialization
        return new Yaml(new SafeConstructor(new LoaderOptions())).load(s);
    }

    Iterable<Object> yamlSafeLoadAll(String s) {
        // ok: java-unsafe-deserialization
        return new Yaml(new SafeConstructor(new LoaderOptions())).loadAll(s);
    }

    // Implementing the Serializable contract, including the standard throws.
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // ok: java-unsafe-deserialization
        Object ignoredValue = in.readObject();
    }

    // Not Java deserialization at all.
    Object pem(PemParser pemParser) throws Exception {
        // ok: java-unsafe-deserialization
        return pemParser.readObject();
    }
}

class PemParser {
    Object readObject() { return null; }
}
