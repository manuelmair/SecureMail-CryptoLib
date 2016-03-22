package at.securemail.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;

public enum SymmetricCipher {

    AES_256(new AESEngine(), 256, 128),
    AES_128(new AESEngine(), 128, 128),
    BLOWFISH(new BlowfishEngine(), 256, 64),
    TWOFISH(new TwofishEngine(), 256, 128),
    //THREEFISH(new ThreefishEngine(512), 512, 512),
    TRIPLE_DES(new DESedeEngine(), 128, 64);

    BlockCipher cipher;
    int keyBit;
    int blockBit;

    SymmetricCipher(BlockCipher cipher, int keyBit, int symBlockBit) {
        this.cipher = cipher;
        this.keyBit = keyBit;
        this.blockBit = symBlockBit;
    }

    static SymmetricCipher decode(byte suiteIndex) throws SecureMailException {
        try {
            return values()[suiteIndex + 128];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new SecureMailException("SymmetricCipher not found");
        }
    }

    byte encode() {
        for (byte b = -128; b < values().length && b < 256; b++)
            if (values()[b + 128] == this)
                return b;
        return 0; // shouldnt happen ever
    }

    BlockCipher getEngine() {
        try {
            return cipher.getClass().newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            return null;
        }
    }

    public int getIndex() {
        for (int i = 0; i < values().length; i++)
            if (values()[i].equals(this))
                return i;
        return -1;
    }

}
