package at.securemail.crypto;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.engines.BlowfishEngine;
import org.spongycastle.crypto.engines.DESedeEngine;
import org.spongycastle.crypto.engines.TwofishEngine;

public enum SymmetricCipher {

    AES_256(new AESEngine(), 256, 128),
    AES_128(new AESEngine(), 128, 128),
    BLOWFISH(new BlowfishEngine(), 256, 64),
    TWOFISH(new TwofishEngine(), 256, 128),
    //THREEFISH(new ThreefishEngine(512), 512, 512),
    TRIPLE_DES(new DESedeEngine(), 128, 64);

    protected BlockCipher cipher;
    protected int keyBit;
    protected int blockBit;

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

    protected byte encode() {
        for (byte b = -128; b < values().length && b < 256; b++)
            if (values()[b + 128] == this)
                return b;
        return 0; // shouldnt happen ever
    }


    protected BlockCipher getEngine(){
        try {
            return cipher.getClass().newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            return null;
        }
    }


}