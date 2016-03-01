package at.securemail.crypto;

public class SecureMailException extends Exception {

    public SecureMailException(String message) {
        super(message);
    }

    public SecureMailException(String message, Exception e) {
        super(message + " | " + e.getMessage());
    }

}
