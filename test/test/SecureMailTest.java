/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import at.securemail.crypto.AsymmetricCipher;
import at.securemail.crypto.AsymmetricKeyPair;
import at.securemail.crypto.HashAlgorithm;
import at.securemail.crypto.SecureAttachment;
import at.securemail.crypto.SecureCipherConfig;
import at.securemail.crypto.SecureFile;
import at.securemail.crypto.SecureMail;
import at.securemail.crypto.SymmetricCipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
//import org.spongycastle.jce.provider.BouncyCastleProvider;

public class SecureMailTest {

    public SecureMailTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        //Security.insertProviderAt(new BouncyCastleProvider(), 0);
    }

    @After
    public void tearDown() {
    }

    @Test
    public void fileEncryptionTest() throws Exception {
        /*byte[] pdfBytes = Files.readAllBytes(Paths.get("C:\\file1.pdf"));
        byte[] pdfEncrypted = SecureFile.encryptFile(pdfBytes, "$_TESTpa55w0rt_@()}");
        byte[] pdfDecrypted = SecureFile.decryptFile(pdfEncrypted, "$_TESTpa55w0rt_@()}");

        if (Arrays.equals(pdfBytes, pdfDecrypted)) {
            System.out.println("File encrypt & decrypt working!");
        } else {
            System.out.println("File encrypt or decrypt fails!");
        }*/
    }

    @Test
    public void emailEncryptionTest() throws Exception {
        String message = "Very secret meSSage!";
        System.out.println("orig: " + message);

        SecureCipherConfig cipherConf = new SecureCipherConfig(
                AsymmetricCipher.RSA_4096,
                SymmetricCipher.AES_256,
                HashAlgorithm.SHA2_256);

        //AsymmetricKeyPair keyPairSender = BasicCrypto.generateKeyPair(cipherConf.asymCipher);
        AsymmetricKeyPair keyPairSender = AsymmetricKeyPair.Create(
                AsymmetricCipher.RSA_4096,
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAimp6x3bkj4UoJpck4NOJtkQ60H0BW/zfAG3v1sFzSgGZBA+n4jfLwF1EveKqGRoa3REUVDKtvFXOM8dhgkpf0Qss91SDhVtormHtE2BpLj7cdFOoG+OxRAhXWSE2luilBWz+yOAs9DQATdHP+VNtU3bVBKm5S9wmuPYKW5nszvV32JfzHta8ZK6LGVNxzuMGacDLijk9eWA85/rRPt7sH2mXcObC4mC8Q9igAdu825DfrPbnkjcqdR5JQbQwoCi7JNnm9ZipucgWT6ktrWmL6yRZlPkg+9isCt29qPM1OA+Yt7kEQ8swJV/YCsSvfXgIwsxctBdVuqZ0XikC+hz+s7q3aA5bdCEZzRilzD9wzCxDhO8ZkpDjh1tAu3PvPfFOt9PYvS5ZpXqEywo46+q5+MT9I9NIImdtEmEam2XUVOL7b4f7Teh8d3GFAmFFZq7Ns1WR1kohBrSw5OJ3hpeewjKsT0L6lOOv4i54rX9SVy5GiSGk2crhzz4lHeDGOat+97AvH5bFM06tahqGtM00lIGurqbRIk8rVsANijIN2KkPv+R06aPRm96CecdTbGaz2TtxOS9hyJ+acWCyRqdt02QDv9uf7R+ohWW6V6e44PV2gNw1GCoCfFtHkPwXH0CG9S52+lgRgadqmT9GRN2zzxs7KlS0ARQH5y8DANll94sCAwEAAQ==",
                "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"
        );

        //AsymmetricKeyPair keyPairRecipient = BasicCrypto.generateKeyPair(cipherConf.asymCipher);
        AsymmetricKeyPair keyPairRecipient = AsymmetricKeyPair.Create(
                AsymmetricCipher.RSA_4096,
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyL6UwSReB2XwhsVruMXiKlVjd7lORPqQxJTgCRTUsUAYWoQjFhCZgIGd3Z1n3juGxe8Zm+vmcxt/ZIKNmFnvOmD8G11heyhKIyu6ufNafD/+FJRPg6iAOMTRZN/MbMbsexzmIc/hXprLUgMK3vdkLgXnHYhQaNCao2Zmw7PjlKbyibg38uYOpW553tLiIIFY6y5FHCwbFX3Ca7hom8b7c7FaDxXXKEayFgucClu/S50PLqGOY+7IVrw1kXVjkVgolI7ln1OKTSvNspJJ0CoO14PcFig1BuIwVKxBFm24Xy4QLjGinwUw/M0y9xDR4dwA0lkfGk0HmSPKwKFgfoWnkIFXOmTtPQPDlZ1k5xtu/d76SUMB+XyE6BVqADD54CSjFyUbB7ggBe8ovUWJLJsjvAsDBAlVWWImSmiZHGu3eOc4O4UmnUMNhl/hf5+F+PSYhjQhN5NMHhKqbwFvI0oTD518XslncvKA6p1NmXm/VjOP7LUwD2jKybi6AKwFt+Bqw8VBrhe1MwavKTOunSpK1W4BT4NOkhNQ4ZQL30eXACAffPR4dmjZdFzDswRIe6PMU2WCvwpuLJlL+tX9rkVUgF+f0gaRRfR/a10XeFBYhwitPUzqfw1MPE6KPcjpsvfy4O25pXL/qRCITcRUurf/c5/gcD9275aIAjN/htPEnycCAwEAAQ==",
                "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"
        );

        SecureMail mail = new SecureMail(cipherConf, message, keyPairRecipient.getPublicKey(), keyPairSender);
        SecureAttachment attachment1 = new SecureAttachment(mail, "file1.pdf", Files.readAllBytes(Paths.get("C:\\file1.pdf")));
        SecureAttachment attachment2 = new SecureAttachment(mail, "file2.png", Files.readAllBytes(Paths.get("C:\\file2.png")));

        // encrypt mail after adding attachments
        String encDataBase64 = mail.encryptMessage();
        byte[] encAttachment1 = attachment1.encrypt();
        byte[] encAttachment2 = attachment2.encrypt();

        // decryption:
        SecureMail receivedMail = SecureMail.parseEncrypted(encDataBase64);

        String decryptedMessage = null;
        switch (receivedMail.getSecureCipherConfig().asymCipher) {
            case RSA_4096:
                // load 4096 key
                decryptedMessage = receivedMail.decryptMessage(keyPairSender.getPublicKey(), keyPairRecipient);
                break;
            case RSA_2048:
                // load 2048 key
                decryptedMessage = receivedMail.decryptMessage(keyPairSender.getPublicKey(), keyPairRecipient);
                break;
            default:
                throw new Exception("something went wrong!");
        }

        byte[] decryptedAttachment1 = SecureAttachment.parseEncrypted(encAttachment1).decryptAttachment(receivedMail);
        byte[] decryptedAttachment2 = SecureAttachment.parseEncrypted(encAttachment2).decryptAttachment(receivedMail);

        if (Arrays.equals(Files.readAllBytes(Paths.get("C:\\file1.pdf")), decryptedAttachment1)) {
            System.out.println("PDF encrypt & decrypt working!");
        } else {
            System.out.println("PDF encrypt or decrypt fails!");
        }

        if (Arrays.equals(Files.readAllBytes(Paths.get("C:\\file2.png")), decryptedAttachment2)) {
            System.out.println("PNG encrypt & decrypt working!");
        } else {
            System.out.println("PNG encrypt or decrypt fails!");
        }

        String[] attachmentNames = receivedMail.attachedFiles.getAttachmentNames();

        System.out.println("attachment 1: " + attachmentNames[0]);
        System.out.println("attachment 2: " + attachmentNames[1]);

        System.out.println("result: " + decryptedMessage);

    }

}
