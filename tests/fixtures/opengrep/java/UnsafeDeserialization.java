// Fixtures for java-unsafe-deserialization.
import java.io.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class UnsafeDeserialization implements Serializable {
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
