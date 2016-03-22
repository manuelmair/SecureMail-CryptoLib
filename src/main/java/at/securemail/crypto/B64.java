package at.securemail.crypto;

import org.bouncycastle.util.encoders.Base64;

// WRAPPER FOR bouncycastle Base64 class
public final class B64 {

    public static String toBase64String(byte[] data) {
        return Base64.toBase64String(data);
    }

    public static byte[] decode(byte[] encode) {
        return Base64.encode(encode);
    }

    public static byte[] decode(String string) {
        return Base64.decode(string);
    }

}