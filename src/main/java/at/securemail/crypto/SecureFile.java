package at.securemail.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;

public class SecureFile {

    public static final int SALT_BIT = 64;
    public static final int BLOCK_SIZE = 128;

    public static byte[] encryptFile(byte[] plain, String password) throws Exception {
        ByteArrayInputStream plainIS = new ByteArrayInputStream(plain);
        ByteArrayOutputStream encOS = new ByteArrayOutputStream();

        // random salt each time => written to file
        byte[] salt = new byte[ SALT_BIT / 8 ];
        BasicCrypto.get().getDefaultPRNG().nextBytes(salt);
        encOS.write(salt);

        // random iv each time => written to file
        byte[] iv = new byte[BLOCK_SIZE / 8];
        BasicCrypto.get().getDefaultPRNG().nextBytes(iv);
        encOS.write(iv);

        // sha1 is only to avoid for signatures
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", CryptoConfig.PROVIDER_NAME);
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKey secretKey = factory.generateSecret(keySpec);
        SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", CryptoConfig.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv), BasicCrypto.get().getDefaultPRNG());

        byte[] input = new byte[BLOCK_SIZE / 8];
        int bytesRead;

        while ((bytesRead = plainIS.read(input)) != -1) {
            byte[] output = cipher.update(input, 0, bytesRead);
            if (output != null)
                encOS.write(output);
        }

        byte[] output = cipher.doFinal();
        if (output != null)
            encOS.write(output);

        return encOS.toByteArray();
    }

    public static byte[] decryptFile(byte[] encrypted, String password) throws Exception{

        ByteArrayInputStream encIS = new ByteArrayInputStream(encrypted);
        ByteArrayOutputStream plainOS = new ByteArrayOutputStream();

        byte[] salt = new byte[ SALT_BIT / 8 ];
        encIS.read(salt);

        byte[] iv = new byte[BLOCK_SIZE / 8];
        encIS.read(iv);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKey tmp = factory.generateSecret(keySpec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv), BasicCrypto.get().getDefaultPRNG());
        byte[] in = new byte[BLOCK_SIZE / 8];
        int read;
        while ((read = encIS.read(in)) != -1) {
            byte[] output = cipher.update(in, 0, read);
            if (output != null)
                plainOS.write(output);
        }
        
        byte[] output = null;
        try{
            output = cipher.doFinal();
        }catch(BadPaddingException bpe){
            throw new InvalidKeyException("Wrong Encryption Key or invalid Storage File");
        }
        
        if (output == null)
            return null;
        else
            plainOS.write(output);

        return plainOS.toByteArray();
    }

}