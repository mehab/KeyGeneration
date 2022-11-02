package org.acme;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import org.jboss.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.*;

@QuarkusMain
public class KeyGeneration {
    public static void main(String... args) {
        Quarkus.run(MyApp.class, args);
    }
    public static class MyApp implements QuarkusApplication {
        Logger logger = Logger.getLogger("poc");

        @Override
        public int run(String... args) {
            try {
                if (!this.secretKeyExists()) {
                    try {
                        SecretKey secretKey = this.generateSecretKey();
                        this.save(secretKey);
                    } catch (NoSuchAlgorithmException var2) {
                        logger.error("An error occurred generating new secret key");
                        logger.error(var2.getMessage());
                    } catch (IOException var3) {
                        logger.error("An error occurred saving newly generated secret key");
                        logger.error(var3.getMessage());
                    }
                }
            } catch (Exception ex) {
                logger.error("Error adding CWEs to database");
                logger.error(ex.getMessage());
            }
            return 0;
        }
        public boolean secretKeyExists() {
            return this.getKeyPath(MyApp.KeyType.SECRET).exists();
        }
        private File getKeyPath(Key key) {
            KeyType keyType = null;
            if (key instanceof PrivateKey) {
                keyType = MyApp.KeyType.PRIVATE;
            } else if (key instanceof PublicKey) {
                keyType = MyApp.KeyType.PUBLIC;
            } else if (key instanceof SecretKey) {
                keyType = MyApp.KeyType.SECRET;
            }

            return this.getKeyPath(keyType);
        }

        private File getKeyPath(KeyType keyType) {
            File var10002 = new File(System.getProperty("user.home")+"/.dependency-track");
            return new File("" + var10002 + File.separator + "keys" + File.separator + keyType.name().toLowerCase() + ".key");
        }

        public SecretKey generateSecretKey() throws NoSuchAlgorithmException {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.init(256, random);
            return keyGen.generateKey();
        }
        public void save(SecretKey key) throws IOException {
            File keyFile = this.getKeyPath(key);
            keyFile.getParentFile().mkdirs();
            OutputStream fos = Files.newOutputStream(keyFile.toPath());

            try {
                ObjectOutputStream oout = new ObjectOutputStream(fos);

                try {
                    oout.writeObject(key);
                } catch (Throwable var9) {
                    try {
                        oout.close();
                    } catch (Throwable var8) {
                        var9.addSuppressed(var8);
                    }

                    throw var9;
                }

                oout.close();
            } catch (Throwable var10) {
                if (fos != null) {
                    try {
                        fos.close();
                    } catch (Throwable var7) {
                        var10.addSuppressed(var7);
                    }
                }

                throw var10;
            }

            if (fos != null) {
                fos.close();
            }

        }
        enum KeyType {
            PRIVATE,
            PUBLIC,
            SECRET;

            private KeyType() {
            }
        }
    }

}