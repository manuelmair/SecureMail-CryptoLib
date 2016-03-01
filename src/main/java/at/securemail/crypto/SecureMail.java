package at.securemail.crypto;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.charset.Charset;
import java.security.SecureRandom;

public class SecureMail {

    public static final int SECMAIL_VERSION = 1;
    public static final Charset CONTENT_CHARSET = Charset.forName("UTF-8");
    protected static final String SECMAIL_IDENTIFER = "?SECMAIL?";

    public AttachedFiles attachedFiles;
    protected AsymmetricKeyPair recipientKeyPair;

    // recipient
    protected byte[] senderPubKey;
    protected byte[] recipientPubKey;
    protected AsymmetricKeyPair senderKeyPair;

    // sender
    protected SecureCipherConfig conf;
    private boolean recipient = true; // true = i received / false = i sent
    private boolean locked = false; // true: signature has been created => file add not possible
    private byte[] encContent; // symmetrically encrypted content
    private byte[] symKey;
    private byte[] symIV;
    private byte[] signature;
    private byte[] content;

    private DataInputStream encDataIS; // raw encrypted data { identifier, version, asym(header), sym(content) }

    private SecureMail() {
    }

    public SecureMail(SecureCipherConfig conf, String content, String recipientPubKeyB64, AsymmetricKeyPair senderKeyPair) throws SecureMailException, IOException {
        this(conf, content.getBytes(CONTENT_CHARSET), DatatypeConverter.parseBase64Binary(recipientPubKeyB64), senderKeyPair);
    }

    public SecureMail(SecureCipherConfig conf, byte[] content, byte[] recipientPubKeyB64, AsymmetricKeyPair senderKeyPair) throws SecureMailException, IOException {
        this.conf = conf;
        this.recipientPubKey = recipientPubKeyB64;
        this.senderKeyPair = senderKeyPair;
        this.senderPubKey = senderKeyPair.publicKey;
        this.content = content;

        if (content == null || conf == null || recipientPubKey == null || senderKeyPair == null)
            throw new SecureMailException("Parameter not specified!");

        recipient = false;
        attachedFiles = new AttachedFiles();

        generateSessionKeyIV();

    }

    public static SecureMail parseEncrypted(String encryptedContentB64) throws SecureMailException, IOException {
        return parseEncrypted(DatatypeConverter.parseBase64Binary(encryptedContentB64));
    }

    public static SecureMail parseEncrypted(byte[] encryptedContent) throws SecureMailException, IOException {

        SecureMail secMail = new SecureMail();

        if (encryptedContent == null || encryptedContent.length == 0)
            throw new SecureMailException("Invalid or empty content!");

        secMail.encDataIS = new DataInputStream(new ByteArrayInputStream(encryptedContent));

        secMail.recipient = true;

        secMail.checkProtocol();

        // decode cipher config:
        secMail.conf = SecureCipherConfig.decode(secMail.encDataIS.readByte(), secMail.encDataIS.readByte(), secMail.encDataIS.readByte());

        return secMail;
    }

    public String encryptMessage() throws SecureMailException, IOException {
        return DatatypeConverter.printBase64Binary(encrypt());
    }

    public byte[] encrypt() throws SecureMailException, IOException {

        ByteArrayOutputStream byteOS = new ByteArrayOutputStream();
        DataOutputStream encDataOS = new DataOutputStream(byteOS);

        encDataOS.writeUTF(SECMAIL_IDENTIFER);
        encDataOS.writeInt(SECMAIL_VERSION);
        encDataOS.write(conf.encode());

        encContent = BasicCrypto.get().encryptSymmetric(symKey, symIV, Bytes.join(attachedFiles.encode(), content), conf);

        signature = signEncryptedContent();
        encryptHeader(encDataOS);

        encDataOS.write(encContent);

        return byteOS.toByteArray();
    }

    public SecureCipherConfig getSecureCipherConfig(){
        return conf;
    }

    public byte[] decryptAttachment(SecureMail receivedMail) throws SecureMailException, IOException {
        return decrypt(receivedMail.senderPubKey, receivedMail.recipientKeyPair);
    }

    public String decryptMessage(String senderPubKeyB64, AsymmetricKeyPair recipientKeyPair) throws SecureMailException, IOException {
        return new String(decrypt(DatatypeConverter.parseBase64Binary(senderPubKeyB64), recipientKeyPair), CONTENT_CHARSET);
    }

    public byte[] decrypt(byte[] senderPubKeyB64, AsymmetricKeyPair recipientKeyPair) throws SecureMailException, IOException {

        this.senderPubKey = senderPubKeyB64;
        this.recipientKeyPair = recipientKeyPair;
        this.recipientPubKey = recipientKeyPair.publicKey;

        decryptHeader(encDataIS);

        // what if encMessageContent.length == 0 ?
        encContent = new byte[encDataIS.available()];
        encDataIS.read(encContent);

        if (!checkSignature())
            throw new SecureMailException("Signature check failed!");

        DataInputStream contentDataIS = new DataInputStream(
                new ByteArrayInputStream(
                        BasicCrypto.get().decryptSymmetric(symKey, symIV, encContent, conf)
                )
        );
        attachedFiles = new AttachedFiles(contentDataIS);
        byte[] message = new byte[contentDataIS.available()];
        contentDataIS.read(message);
        return message;
    }

    private void decryptHeader(DataInputStream encryptedIS) throws SecureMailException, IOException {

        // read block count + first chunk
        byte[] encryptedChunk = new byte[conf.asymCipher.blockSizeBit / 8];
        encryptedIS.read(encryptedChunk);
        byte[] decryptChunk = BasicCrypto.get().decryptAsymmetric(recipientKeyPair.privateKey, encryptedChunk, conf);
        int blockCount = (decryptChunk[0] + 128);

        ByteArrayOutputStream headerEncodedOS = new ByteArrayOutputStream();
        headerEncodedOS.write(decryptChunk);

        for (int i = 1; i < blockCount; i++) {
            encryptedIS.read(encryptedChunk);
            decryptChunk = BasicCrypto.get().decryptAsymmetric(recipientKeyPair.privateKey, encryptedChunk, conf);
            headerEncodedOS.write(decryptChunk);
        }

        ByteArrayInputStream headerEncodedIS = new ByteArrayInputStream(headerEncodedOS.toByteArray());

        // remove block count byte from header
        headerEncodedIS.skip(1);

        symKey = new byte[conf.symCipher.keyBit / 8];
        headerEncodedIS.read(symKey);

        symIV = new byte[conf.symCipher.blockBit / 8];
        headerEncodedIS.read(symIV);

        signature = new byte[conf.asymCipher.blockSizeBit / 8];
        headerEncodedIS.read(signature);

        // stupid way to get the current signature length
        // additionally: what if signature is signed by CA or other people => different length?
        //int signatureLength = createSignature(Bytes.join(symKey,symIV,attachedFiles.encode(), encContent),recipientKeyPair.privateKey, conf).length;
        //signature = Bytes.read(headerEncoded, signatureLength);
        //headerEncoded = Bytes.chop(headerEncoded, signatureLength);

        // better idea: put signature to the end and use remainder

        /*int signatureEncryptedLen = getOutputSizeSymmetric(symKey, symIV, (conf.asymCipher.blockSizeBit / 8), conf);
        byte[] signatureEncrypted = new byte[signatureEncryptedLen + 16];
        encDataIS.read(signatureEncrypted);

        signature = decryptSymmetric(symKey, symIV, signatureEncrypted, conf);*/
    }

    private void encryptHeader(DataOutputStream encHeaderOS) throws SecureMailException, IOException {
        byte[] header = Bytes.join(new byte[]{0}, symKey, symIV, signature);

        int blockCount = header.length / conf.asymCipher.inputBlockSize;
        if (header.length % conf.asymCipher.inputBlockSize > 0) {
            blockCount++;
        }
        if (blockCount > 255) {
            throw new SecureMailException("Header size too big for encoding! Too large signature?");
        }
        header[0] = (byte) (blockCount - 128);

        byte[] curBlock; // size: block size - padding
        byte[] encryptedBlock = new byte[conf.asymCipher.blockSizeBit / 8];

        for (int i = 1; i < blockCount; i++) {
            curBlock = Bytes.read(header, conf.asymCipher.inputBlockSize);
            header = Bytes.chop(header, conf.asymCipher.inputBlockSize);
            encryptedBlock = BasicCrypto.get().encryptAsymmetric(recipientPubKey, curBlock, conf);
            encHeaderOS.write(encryptedBlock);
        }

        encryptedBlock = BasicCrypto.get().encryptAsymmetric(recipientPubKey, header, conf);
        encHeaderOS.write(encryptedBlock);
    }

    private void checkProtocol() throws SecureMailException, IOException {
        if (!encDataIS.readUTF().equals(SECMAIL_IDENTIFER)) {
            throw new SecureMailException("No SecureMail Header detected!");
        }

        int version = encDataIS.readInt();
        if (version > SECMAIL_VERSION) {
            throw new SecureMailException("SecMail Version specified is higher than runtime version");
        }
    }

    private void generateSessionKeyIV() throws SecureMailException {
        SecureRandom secRand = BasicCrypto.get().getDefaultPRNG();
        symKey = new byte[conf.symCipher.keyBit / 8];
        secRand.nextBytes(symKey);
        symIV = new byte[conf.symCipher.blockBit / 8];
        secRand.nextBytes(symIV);
    }

    private byte[] signEncryptedContent() throws SecureMailException {

        // data which is not signed can be manipulated if adversary is in possession of the private key: e.g. attachment filenames, date, etc. MUST be signed!

        byte[] rawEncryptedHeader = BasicCrypto.get().encryptRawAsymmetric(recipientPubKey, Bytes.join(symKey, symIV), conf);
        byte[] encryptedDataForSigning = Bytes.join(rawEncryptedHeader, encContent);

        return BasicCrypto.get().createSignature(encryptedDataForSigning, senderKeyPair.privateKey, conf);
    }

    private boolean checkSignature() throws SecureMailException {

        byte[] encHeader = BasicCrypto.get().encryptRawAsymmetric(recipientPubKey, Bytes.join(symKey, symIV), conf);
        byte[] encryptedDataForSigning = Bytes.join(encHeader, encContent);

        return BasicCrypto.get().verifySignature(signature, senderPubKey, encryptedDataForSigning, conf);
    }

    /*private byte[] encryptHeader() throws SecureMailException {
        header = Bytes.join(new byte[]{0}, symKey, symIV);

        int blockCount = header.length / conf.asymCipher.inputBlockSize;
        if(header.length % conf.asymCipher.inputBlockSize > 0){
            blockCount++;
        }
        System.out.println("header.length: " + header.length + " | blockCount: " + blockCount);
        if(blockCount > 255){
            throw new SecureMailException("Header size too big for encoding! Too large signature?");
        }
        header[0] = (byte)(blockCount - 128);

        byte[] encHeader = new byte[0];
        byte[] curBlock;
        for(int i = 1; i < blockCount; i++){
            curBlock = Bytes.read(header, conf.asymCipher.inputBlockSize);
            curBlock = encryptAsymmetric(recipientPubKey, curBlock, conf);
            encHeader = Bytes.join(encHeader, curBlock);
            header = Bytes.chop(header, conf.asymCipher.inputBlockSize);
        }

        curBlock = encryptAsymmetric(recipientPubKey, header, conf);
        return Bytes.join(encHeader, curBlock);
    }

    private void decryptHeader() throws SecureMailException {

        // read block count + first chunk
        byte[] decryptChunk = Bytes.read(encData, conf.asymCipher.blockSizeBit / 8);
        decryptChunk = decryptAsymmetric(recipientKeyPair.privateKey, decryptChunk, conf);
        int blockCount = (decryptChunk[0] + 128);

        // remove block count byte from header
        decryptChunk = Bytes.chop(decryptChunk, 1);
        byte[] headerEncoded = decryptChunk;

        encData = Bytes.chop(encData, conf.asymCipher.blockSizeBit / 8);

        for(int i = 1; i < blockCount; i++){
            decryptChunk = Bytes.read(encData, conf.asymCipher.blockSizeBit / 8);
            decryptChunk = decryptAsymmetric(recipientKeyPair.privateKey, decryptChunk, conf);
            headerEncoded = Bytes.join(headerEncoded, decryptChunk);
            encData = Bytes.chop(encData, conf.asymCipher.blockSizeBit / 8);
        }

        symKey = Bytes.read(headerEncoded, conf.cipher.keyBit / 8);
        headerEncoded = Bytes.chop(headerEncoded, conf.cipher.keyBit / 8);

        symIV = Bytes.read(headerEncoded, conf.cipher.blockBit / 8);
        headerEncoded = Bytes.chop(headerEncoded, conf.cipher.blockBit / 8);

        //
        // add filename decoding !!!
        //
        attachedFiles = new AttachedFiles(); // <- dummy

    }*/

}