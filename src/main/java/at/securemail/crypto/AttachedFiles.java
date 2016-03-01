package at.securemail.crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AttachedFiles {

    public short attachmentCount = 0;
    private List<String> fileNames;

    AttachedFiles() {
        fileNames = new ArrayList<String>();
    }

    AttachedFiles(DataInputStream encodedDataIS) throws IOException, SecureMailException {
        fileNames = new ArrayList<String>();
        attachmentCount = encodedDataIS.readShort();

        for (int i = 0; i < attachmentCount; i++) {
            fileNames.add(encodedDataIS.readUTF());
        }
    }

    public void addAttachmentFileName(String fileName) throws SecureMailException {
        if (attachmentCount >= Short.MAX_VALUE)
            throw new SecureMailException("Maximum attachment count of " + (Short.MAX_VALUE + Short.MIN_VALUE) + " exceeded!");

        fileNames.add(fileName);
        attachmentCount++;
    }

    byte[] encode() throws IOException {
        ByteArrayOutputStream encodedOS = new ByteArrayOutputStream();
        DataOutputStream encodedDataOS = new DataOutputStream(encodedOS);

        encodedDataOS.writeShort(attachmentCount);
        for (String fileName : fileNames) {
            encodedDataOS.writeUTF(fileName);
        }

        encodedDataOS.flush();
        encodedOS.flush();
        return encodedOS.toByteArray();
    }

    public String[] getAttachmentNames() {
        String[] fileNameArr = new String[fileNames.size()];
        return fileNames.toArray(fileNameArr);
    }

}