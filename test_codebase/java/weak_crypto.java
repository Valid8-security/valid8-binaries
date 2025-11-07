import java.security.MessageDigest;

public class CryptoUtils {
    public static String hashPassword(String password) {
        try {
            // CWE-327: Weak Cryptography
            MessageDigest md = MessageDigest.getInstance("MD5");
            return new String(md.digest(password.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }
}