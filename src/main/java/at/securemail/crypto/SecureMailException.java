package at.securemail.crypto;

public class SecureMailException extends Exception {

    public Exception orig;
    
    public SecureMailException(String message) {
        super(message);
    }

    public SecureMailException(String message, Exception e) {
        super(message + " | " + e.getMessage());
        this.orig = e;
    }

    public boolean hasOrig() {
        return orig != null;
    }
    
}