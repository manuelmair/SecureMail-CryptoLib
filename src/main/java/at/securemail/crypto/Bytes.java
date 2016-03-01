package at.securemail.crypto;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

public class Bytes {

    public static final int INT = 4;
    public static final int SHORT = 2;

    public static byte[] join(byte[]... b) {
        ArrayList<Byte> joined = new ArrayList<Byte>();
        for (byte[] i : b) {
            for (int x = 0; x < i.length; x++)
                joined.add(i[x]);
        }
        byte ret[] = new byte[joined.size()];
        for (int i = 0; i < joined.size(); i++) {
            ret[i] = joined.get(i);
        }
        return ret;
    }

    public static byte[] read(byte[] b2chop, int readBytes) {
        return Arrays.copyOfRange(b2chop, 0, readBytes);
    }

    public static byte[] chop(byte[] b2chop, int removeBytes) {
        return Arrays.copyOfRange(b2chop, removeBytes, b2chop.length);
    }

    public static String toString(byte[] b) {
        return new String(b);
    }

    public static byte[] getBytes(int i) {
        return ByteBuffer.allocate(4).putInt(i).array();
    }

    public static int getInt(byte[] b) {
        return ByteBuffer.wrap(b).getInt();
    }

}
