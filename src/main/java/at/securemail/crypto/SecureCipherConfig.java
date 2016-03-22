package at.securemail.crypto;

import java.io.Serializable;

public class SecureCipherConfig implements Serializable {

    private static final long serialVersionUID = 1L;

    public AsymmetricCipher asymCipher;
    public SymmetricCipher symCipher;
    public HashAlgorithm hashAlgorithm;

    public SecureCipherConfig(AsymmetricCipher asymCipher, SymmetricCipher symCipher, HashAlgorithm hashAlgorithm) {
        this.asymCipher = asymCipher;
        this.symCipher = symCipher;
        this.hashAlgorithm = hashAlgorithm;
    }

    static SecureCipherConfig decode(byte asymByte, byte symByte, byte hashByte) throws SecureMailException {
        return new SecureCipherConfig(AsymmetricCipher.decode(asymByte), SymmetricCipher.decode(symByte), HashAlgorithm.decode(hashByte));
    }

    public byte[] encode() {
        return new byte[]{asymCipher.encode(), symCipher.encode(), hashAlgorithm.encode()};
    }

}
