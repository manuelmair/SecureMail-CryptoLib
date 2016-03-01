package at.securemail.crypto;

import org.spongycastle.crypto.*;
import org.spongycastle.crypto.encodings.PKCS1Encoding;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.PKCS7Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.PSSSigner;
import org.spongycastle.crypto.util.PrivateKeyFactory;
import org.spongycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.security.*;

public class BasicCrypto {

    private static BasicCrypto instance = null;

    public static BasicCrypto get() {
        if (instance == null)
            instance = new BasicCrypto();
        return instance;
    }

    byte[] encryptRawAsymmetric(byte[] recipientPublicKey, byte[] original, SecureCipherConfig conf) throws SecureMailException {
        AsymmetricKeyParameter publicKey;
        try {
            publicKey = PublicKeyFactory.createKey(recipientPublicKey);
        } catch (IOException e) {
            throw new SecureMailException("PublicKey is not valid - IOException: " + e.getMessage());
        }

        AsymmetricBlockCipher engine = conf.asymCipher.getEngine();
        engine.init(true, publicKey);

        byte[] encrypted;
        try {
            encrypted = engine.processBlock(original, 0, original.length);
        } catch (InvalidCipherTextException e) {
            throw new SecureMailException("Asymmetric encryption failed - Invalid Cipher Text: " + e.getMessage());
        }
        return encrypted;
    }

    byte[] encryptAsymmetric(byte[] recipientPublicKey, byte[] original, SecureCipherConfig conf) throws SecureMailException {
        AsymmetricKeyParameter publicKey;
        try {
            publicKey = PublicKeyFactory.createKey(recipientPublicKey);
        } catch (IOException e) {
            throw new SecureMailException("PublicKey is not valid - IOException: " + e.getMessage());
        }
        AsymmetricBlockCipher engine = conf.asymCipher.getEngine();

        engine = new PKCS1Encoding(engine);
        engine.init(true, publicKey);

        byte[] encrypted;
        try {
            encrypted = engine.processBlock(original, 0, original.length);
        } catch (InvalidCipherTextException e) {
            throw new SecureMailException("Asymmetric encryption failed - Invalid Cipher Text: " + e.getMessage());
        }
        return encrypted;
    }

    byte[] decryptAsymmetric(byte[] recipientPrivateKey, byte[] encrypted, SecureCipherConfig conf) throws SecureMailException {
        
        AsymmetricKeyParameter privateKey;
        try {
            privateKey = PrivateKeyFactory.createKey(recipientPrivateKey);
        } catch (IOException e) {
            throw new SecureMailException("PrivateKey is not valid - IOException: " + e.getMessage());
        }
        
        AsymmetricBlockCipher engine = conf.asymCipher.getEngine();
        engine = new PKCS1Encoding(engine);
        
        engine.init(false, privateKey);
        
        byte[] original;
        try {
            original = engine.processBlock(encrypted, 0, encrypted.length);
        } catch (InvalidCipherTextException e) {
            throw new SecureMailException("Asymmetric decryption failed - Invalid Cipher Text: " + e.getMessage());
        }
        return original;
    }

    byte[] encryptSymmetric(byte[] key, byte[] iv, byte[] original, SecureCipherConfig conf) throws SecureMailException {
        KeyParameter keyParam = new KeyParameter(key);
        CipherParameters params = new ParametersWithIV(keyParam, iv);

        // setup AES cipher in CBC mode with PKCS7 padding
        BlockCipherPadding padding = new PKCS7Padding();
        BlockCipher engine = conf.symCipher.getEngine();

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), padding);
        cipher.reset();
        cipher.init(true, params);

        // temporary buffer for encrypted content (including padding!)
        byte[] encrypted = new byte[cipher.getOutputSize(original.length)];
        int encLen = cipher.processBytes(original, 0, original.length, encrypted, 0);
        try {
            encLen += cipher.doFinal(encrypted, encLen);
        } catch (InvalidCipherTextException e) {
            throw new SecureMailException("Symmetric encryption failed - Invalid Cipher Text: " + e.getMessage());
        }
        return encrypted;
    }

    byte[] decryptSymmetric(byte[] key, byte[] iv, byte[] encrypted, SecureCipherConfig conf) throws SecureMailException {
        KeyParameter keyParam = new KeyParameter(key);
        CipherParameters params = new ParametersWithIV(keyParam, iv);

        BlockCipher engine = conf.symCipher.getEngine();

        // setup cipher in CBC mode with PKCS7 padding
        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), padding);
        cipher.reset();
        cipher.init(false, params);

        // temporary buffer for encrypted content (including padding!)
        byte[] originalPadded = new byte[encrypted.length];
        int origLen = cipher.processBytes(encrypted, 0, encrypted.length, originalPadded, 0);
        try {
            origLen += cipher.doFinal(originalPadded, origLen);
        } catch (InvalidCipherTextException e) {
            throw new SecureMailException("Symmetric encryption failed - Invalid Cipher Text: " + e.getMessage());
        }

        byte[] original = new byte[origLen];
        System.arraycopy(originalPadded, 0, original, 0, origLen);
        return original;
    }

    int getOutputSizeSymmetric(byte[] key, int inputSize, SecureCipherConfig conf) throws SecureMailException {
        KeyParameter keyParam = new KeyParameter(key);
        CipherParameters params = new ParametersWithIV(keyParam, new byte[conf.symCipher.blockBit / 8]);

        BlockCipher engine = conf.symCipher.getEngine();

        // setup cipher in CBC mode with PKCS7 padding
        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), padding);
        cipher.reset();
        cipher.init(false, params);

        return cipher.getOutputSize(inputSize);
    }

    boolean verifySignature(byte[] dataSignature, byte[] publicKeyBytes, byte[] data, SecureCipherConfig conf) throws SecureMailException {
        AsymmetricKeyParameter publicKey;
        try {
            publicKey = PublicKeyFactory.createKey(publicKeyBytes);
        } catch (IOException e) {
            throw new SecureMailException("PrivateKey is not valid - IOException: " + e.getMessage());
        }

        PSSSigner signEngine;
        Digest digest = conf.hashAlgorithm.getDigest();

        signEngine = new PSSSigner(new RSAEngine(), digest, 20);

        signEngine.init(false, new ParametersWithRandom(publicKey, getDefaultPRNG()));
        signEngine.update(data, 0, data.length);
        return signEngine.verifySignature(dataSignature);
    }


    byte[] createSignature(byte[] data, byte[] privateKeyBytes, SecureCipherConfig conf) throws SecureMailException {
        AsymmetricKeyParameter privateKey;
        try {
            privateKey = PrivateKeyFactory.createKey(privateKeyBytes);
        } catch (IOException e) {
            throw new SecureMailException("PrivateKey is not valid - IOException: " + e.getMessage());
        }

        PSSSigner signEngine;
        Digest digest = conf.hashAlgorithm.getDigest();

        signEngine = new PSSSigner(new RSAEngine(), digest, 20);

        signEngine.init(true, new ParametersWithRandom(privateKey, getDefaultPRNG()));
        signEngine.update(data, 0, data.length);
        try {
            return signEngine.generateSignature();
        } catch (CryptoException e) {
            throw new SecureMailException("Signature generation failed: " + e.getMessage());
        }
    }

    public AsymmetricKeyPair generateKeyPair(AsymmetricCipher asymCipher) throws NoSuchAlgorithmException, NoSuchProviderException, SecureMailException {

        KeyPairGenerator keyGen;
        KeyPair keyPair;
        PrivateKey privateKey;
        PublicKey publicKey;

        switch (asymCipher) {
            case RSA_4096:
                keyGen = KeyPairGenerator.getInstance("RSA", "BC");
                keyGen.initialize(4096, getDefaultPRNG());
                keyPair = keyGen.genKeyPair();
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
                break;
            case RSA_2048:
                keyGen = KeyPairGenerator.getInstance("RSA", "BC");
                keyGen.initialize(2048, getDefaultPRNG());
                keyPair = keyGen.genKeyPair();
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
                break;
            /*case ElGamal_1024:
                keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
                keyGen.initialize(1024, getDefaultPRNG());
                keyPair = keyGen.generateKeyPair();
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
                break;*/
            default:
                return null;
        }

        return AsymmetricKeyPair.Create(asymCipher, publicKey.getEncoded(), privateKey.getEncoded());
    }

    SecureRandom getDefaultPRNG() {
        return new SecureRandom();
        /*try {
            SecureRandom secRand = SecureRandom.getInstanceStrong();
            System.out.println("provider: " + secRand.getProvider() + " | algo: " + secRand.getAlgorithm());
            return SecureRandom.getInstance("SHA1PRNG", "BC");
            //return new SecureRandom(new DigestRandomGenerator(new SHA256Digest()));
        }catch(NoSuchAlgorithmException e){
            throw new SecureMailException("Pseudo random number generator 'SHA1PRNG' not found! ", e);
        }catch(NoSuchProviderException e){
            throw new SecureMailException("BC Provider not found!", e);
        }*/
    }


}