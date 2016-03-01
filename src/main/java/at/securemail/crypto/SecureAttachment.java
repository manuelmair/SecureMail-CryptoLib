package at.securemail.crypto;

import java.io.IOException;

public class SecureAttachment extends SecureMail {

    public SecureAttachment(SecureMail mail, String fileName, byte[] content) throws SecureMailException, IOException {
        // encrypt
        super(mail.conf, content, mail.recipientPubKey, mail.senderKeyPair);
        mail.attachedFiles.addAttachmentFileName(fileName);
    }

    public static SecureMail parseEncrypted(byte[] encryptedContent) throws SecureMailException, IOException {
        // decrypt
        return SecureMail.parseEncrypted(encryptedContent);
    }

    @Override
    public byte[] encrypt() throws SecureMailException, IOException {
        return super.encrypt();
    }
}
