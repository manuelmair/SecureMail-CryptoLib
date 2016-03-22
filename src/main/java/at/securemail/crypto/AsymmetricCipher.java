package at.securemail.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;

import java.io.Serializable;

public enum AsymmetricCipher implements Serializable{
    
    RSA_4096(new RSAEngine(), 4096, 501),
    RSA_2048(new RSAEngine(), 2048, 245);

    private static final long serialVersionUID = 1L;
    
    private AsymmetricBlockCipher cipher;
    int blockSizeBit; // this is equal to key size & block size
    int inputBlockSize;

    AsymmetricCipher(AsymmetricBlockCipher cipher, int blockSizeBit, int inputBlockSize) {
        this.cipher = cipher;
        this.blockSizeBit = blockSizeBit;
        this.inputBlockSize = inputBlockSize;
    }

    static AsymmetricCipher decode(byte suiteIndex) throws SecureMailException {
        try {
            return values()[suiteIndex + 128];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new SecureMailException("AsymmetricCipher not found");
        }
    }

    byte encode() {
        for (byte b = -128; b < values().length && b < 256; b++)
            if (values()[b + 128] == this)
                return b;
        return 0; // in a sane environment this is impossible
    }

    AsymmetricBlockCipher getEngine(){
        try {
            return cipher.getClass().newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            return null;
        }
    }

    public int getIndex() {
        for(int i = 0; i < values().length; i++)
            if(values()[i].equals(this))
                return i;
        return -1;
    }

}