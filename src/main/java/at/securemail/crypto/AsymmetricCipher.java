package at.securemail.crypto;

import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.engines.RSAEngine;

public enum AsymmetricCipher {

    RSA_4096(new RSAEngine(), 4096, 501),
    RSA_2048(new RSAEngine(), 2048, 245);

    private AsymmetricBlockCipher cipher;
    protected int blockSizeBit; // this is equal to key size & block size
    protected int inputBlockSize;

    AsymmetricCipher(AsymmetricBlockCipher cipher, int blockSizeBit, int inputBlockSize) {
        this.cipher = cipher;
        this.blockSizeBit = blockSizeBit;
        this.inputBlockSize = inputBlockSize;
    }

    protected static AsymmetricCipher decode(byte suiteIndex) throws SecureMailException {
        try {
            return values()[suiteIndex + 128];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new SecureMailException("AsymmetricCipher not found");
        }
    }

    protected byte encode() {
        for (byte b = -128; b < values().length && b < 256; b++)
            if (values()[b + 128] == this)
                return b;
        return 0; // in a sane environment this is impossible
    }

    protected AsymmetricBlockCipher getEngine(){
        try {
            return cipher.getClass().newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            return null;
        }
    }

}