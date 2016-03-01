package at.securemail.crypto;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

import static at.securemail.crypto.BasicCrypto.*;

public class AsymmetricKeyPair {

    byte[] publicKey;
    byte[] privateKey;
    private AsymmetricCipher cipherType;

    private AsymmetricKeyPair(AsymmetricCipher cipherType, byte[] publicKey, byte[] privateKey) {
        this.cipherType = cipherType;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static AsymmetricKeyPair Create(AsymmetricCipher cipherType, byte[] publicKey, byte[] privateKey) throws SecureMailException {
        AsymmetricKeyPair createdKeyPair = new AsymmetricKeyPair(
                cipherType,
                publicKey,
                privateKey
        );
        if (cipherType == null || publicKey.length == 0 || privateKey.length == 0 || !checkKeyValidity(createdKeyPair)) {
            throw new SecureMailException("One of the keys is invalid and/or does not fit the cipher type!");
        }
        return createdKeyPair;
    }

    public static AsymmetricKeyPair Create(AsymmetricCipher cipherType, String publicKeyB64, String privateKeyB64) throws SecureMailException {
        return AsymmetricKeyPair.Create(cipherType, DatatypeConverter.parseBase64Binary(publicKeyB64), DatatypeConverter.parseBase64Binary(privateKeyB64));
    }

    public static boolean checkKeyValidity(AsymmetricKeyPair createdKeyPair) throws SecureMailException {
        byte[] randomContent = new byte[createdKeyPair.cipherType.inputBlockSize];
        BasicCrypto.get().getDefaultPRNG().nextBytes(randomContent);
        byte[] encryptTest = BasicCrypto.get().encryptAsymmetric(
                createdKeyPair.publicKey,
                randomContent,
                new SecureCipherConfig(
                        createdKeyPair.cipherType,
                        null,
                        null
                )
        );
        encryptTest = BasicCrypto.get().decryptAsymmetric(
                createdKeyPair.privateKey,
                encryptTest,
                new SecureCipherConfig(
                        createdKeyPair.cipherType,
                        null,
                        null
                )
        );
        return Arrays.equals(randomContent, encryptTest);
    }

    public AsymmetricCipher getAsymCipherType() {
        // cipherType itself should be private
        return cipherType;
    }

    public String getPublicKey() {
        return DatatypeConverter.printBase64Binary(publicKey);
    }

    public String getPrivateKey() {
        return DatatypeConverter.printBase64Binary(privateKey);
    }

}