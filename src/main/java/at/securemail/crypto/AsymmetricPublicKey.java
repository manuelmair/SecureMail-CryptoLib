package at.securemail.crypto;

import javax.xml.bind.DatatypeConverter;

public class AsymmetricPublicKey {

    private AsymmetricCipher cipherType;
    private byte[] publicKey;

    private AsymmetricPublicKey(AsymmetricCipher cipherType, byte[] publicKey) {
        this.cipherType = cipherType;
        this.publicKey = publicKey;
    }

    static AsymmetricPublicKey Create(AsymmetricCipher cipherType, byte[] publicKey) throws SecureMailException {
        AsymmetricPublicKey asymPubKey = new AsymmetricPublicKey(cipherType, publicKey);
        if (cipherType == null || publicKey.length == 0 || !checkKeyValidity(asymPubKey))
            throw new SecureMailException("The key is invalid and/or does not fit the cipher type!");
        return asymPubKey;
    }

    public static AsymmetricPublicKey Create(AsymmetricCipher cipherType, String publicKeyB64) throws SecureMailException {
        return AsymmetricPublicKey.Create(cipherType, DatatypeConverter.parseBase64Binary(publicKeyB64));
    }

    public static boolean checkKeyValidity(AsymmetricPublicKey createdKeyPair) throws SecureMailException {
        byte[] randomContent = new byte[createdKeyPair.cipherType.inputBlockSize];
        BasicCrypto.get().getDefaultPRNG().nextBytes(randomContent);
        BasicCrypto.get().encryptAsymmetric(
                createdKeyPair.publicKey,
                randomContent,
                new SecureCipherConfig(
                        createdKeyPair.cipherType,
                        null,
                        null
                )
        );
        return true;
    }

    public AsymmetricCipher getAsymCipherType() {
        // cipherType itself should be private
        return cipherType;
    }

    public String getPublicKey() {
        return DatatypeConverter.printBase64Binary(publicKey);
    }

}