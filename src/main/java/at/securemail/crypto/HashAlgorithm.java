package at.securemail.crypto;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;

public enum HashAlgorithm {

    SHA3_384(new SHA384Digest(), 384),
    SHA2_512(new SHA512Digest(), 512),
    SHA2_256(new SHA256Digest(), 256);

    private Digest digest;
    protected int hashBits;

    HashAlgorithm(Digest digest, int hashBits) {
        this.digest = digest;
        this.hashBits = hashBits;
    }

    protected static HashAlgorithm decode(byte suiteIndex) throws SecureMailException {
        try {
            return values()[suiteIndex + 128];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new SecureMailException("HashAlgorithm not found");
        }
    }

    protected byte encode() {
        for (byte b = -128; b < values().length && b < 256; b++)
            if (values()[b + 128] == this)
                return b;
        return 0; //  shouldnt happen ever
    }

    protected Digest getDigest(){
        try {
            return digest.getClass().newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            return null;
        }
    }

}