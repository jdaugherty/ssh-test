package net.jdresources.ssh

import groovy.util.logging.Slf4j
import org.apache.commons.io.FileUtils
import org.apache.sshd.common.config.keys.KeyUtils
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter
import org.apache.sshd.common.util.security.SecurityUtils
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider

import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.KeyPair

@Slf4j
class SshUtil {
    /**
     * Easily create an input stream from a given string
     */
    static InputStream toInputStream(String input, Charset charset) {
        new ByteArrayInputStream(input.getBytes(charset))
    }

    /**
     * Either returns the string as-is since it's a key or reads the location in it from the file system and the content of that file
     */
    static String readIfFile(String possiblePath) {
        if (!possiblePath || possiblePath.startsWith('---')) {
            return possiblePath
        }

        try {
            Path path = Paths.get(possiblePath)
            if (!Files.exists(path)) {
                if (Files.exists(path.parent)) {
                    //Definitely expected a path but the file doesn't exist
                    return null
                }

                //Complete path is wrong, let the key extraction fail
                log.warn("Configured Key Path does not exist.  Assuming path is a key.")
                return possiblePath
            }

            //Found a file, attempt to read from it and let the system error if the key couldn't be found.
            path.toFile().getText(Charset.defaultCharset().name())
        }
        catch (Exception ignored) {
            return possiblePath
        }
    }

    /**
     * Creates a java.security.KeyPair from the given string containing a key pair
     */
    static KeyPair readKeyPair(String keyPair) {
        InputStream input = toInputStream(keyPair, Charset.defaultCharset())

        List<KeyPair> pairs
        try {
            pairs = SecurityUtils.loadKeyPairIdentities(null, null, input, null).toList()
        }
        catch (e) {
            throw new IllegalArgumentException("Unable to extract private key: ", e)
        }

        if (!pairs) {
            //do not log the key value since it could lead to a compromise in security
            throw new IllegalStateException("Unable to extract private key: No PEM was parsed.")
        } else if (pairs.size() > 1) {
            throw new IllegalStateException("Multiple KeyPairs were found.  Only 1 is supported.")
        }

        pairs[0]
    }

    /**
     * Creates a java.security.KeyPair from the given string containing a key pair or if it's a file location of the keypair
     */
    static KeyPair loadKeyPair(String privateKeyOrPath) {
        privateKeyOrPath = readIfFile(privateKeyOrPath?.trim())
        if (!privateKeyOrPath) {
            throw new IllegalArgumentException("Private Key is required to authenticate to a remote server.")
        }

        readKeyPair(privateKeyOrPath)
    }

    /**
     * Generates a KeyPair from scratch
     * @param algorithm the algorithm to use
     */
    static KeyPair generateKeyPair(String algorithm = KeyUtils.EC_ALGORITHM) {
        Path holding = Files.createTempDirectory("sshTemp")
        try {
            FileUtils.forceMkdir(holding.resolve('.ssh').toFile())
            SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider(holding.resolve('.ssh').resolve("${UUID.randomUUID()}.key"))
            provider.algorithm = algorithm
            List<KeyPair> keys = provider.loadKeys(null)
            return keys[0]
        }
        finally {
            FileUtils.deleteQuietly(holding.toFile())
        }
    }

    /**
     * Uses OpenSSH encoding to write a private key into a single string for writing to a file
     */
    static String convertPrivateKey(KeyPair keyPair, String comment = null) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()

        OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(keyPair, comment, null, outputStream)

        outputStream.toString()
    }

    /**
     * Uses OpenSSH encoding to write a public key into a single string for writing to a file
     */
    static String convertPublicKey(KeyPair keyPair, String comment = null) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()

        OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(keyPair, comment, outputStream)

        outputStream.toString()
    }
}
