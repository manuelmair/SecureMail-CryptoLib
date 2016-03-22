package at.securemail.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

public enum HashAlgorithm {

    SHA2_256(new SHA256Digest(), 256),
    SHA3_384(new SHA384Digest(), 384),
    SHA2_512(new SHA512Digest(), 512);

    private Digest digest;
    int hashBits;

    HashAlgorithm(Digest digest, int hashBits) {
        this.digest = digest;
        this.hashBits = hashBits;
    }

    static HashAlgorithm decode(byte suiteIndex) throws SecureMailException {
        try {
            return values()[suiteIndex + 128];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new SecureMailException("HashAlgorithm not found");
        }
    }

    byte encode() {
        for (byte b = -128; b < values().length && b < 256; b++)
            if (values()[b + 128] == this)
                return b;
        return 0; //  shouldnt happen ever
    }

    Digest getDigest(){
        try {
            return digest.getClass().newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            return null;
        }
    }

    @Override
    public String toString() {
        return super.name();
    }

    public int getIndex() {
        for(int i = 0; i < values().length; i++)
            if(values()[i].equals(this))
                return i;
        return -1;
    }

}