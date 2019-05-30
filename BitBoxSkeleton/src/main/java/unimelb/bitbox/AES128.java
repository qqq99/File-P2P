package unimelb.bitbox;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import java.awt.RenderingHints.Key;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

// to encode public key
public class AES128 {
    // encrypt string using key
    public static String Encrypt(String sSrc, String sKey) throws Exception {
        Key secretKey = getKey(sKey);
        /*byte[] raw = sKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");*/
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, (java.security.Key) secretKey);
        byte[] encrypted = cipher.doFinal(sSrc.getBytes(StandardCharsets.UTF_8));

        // base 64 encode
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // decrypt string using key
    public static String Decrypt(String sSrc, String sKey) throws Exception {
        try {
            Key secretKey = getKey(sKey);
            /*byte[] raw = sKey.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");*/
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, (java.security.Key) secretKey);
            // use base 64  to decode first
            byte[] encrypted1 = Base64.getDecoder().decode(sSrc);
            try {
                byte[] original = cipher.doFinal(encrypted1);
                return new String(original, StandardCharsets.UTF_8);
            } catch (Exception e) {
                System.out.println(e.toString());
                return null;
            }
        } catch (Exception ex) {
            System.out.println(ex.toString());
            return null;
        }
    }
    public static Key getKey(String keySeed) {  
        if (keySeed == null) {  
            keySeed = System.getenv("AES_SYS_KEY");  
        }  
        if (keySeed == null) {  
            keySeed = System.getProperty("AES_SYS_KEY");  
        }  
        if (keySeed == null || keySeed.trim().length() == 0) {  
            keySeed = "a1b2c3d4%&*"; //random string
        }  
        try {  
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");  
            secureRandom.setSeed(keySeed.getBytes());  
            KeyGenerator generator = KeyGenerator.getInstance("AES/ECB/PKCS5Padding");  
            generator.init(secureRandom);  
            return (Key) generator.generateKey();  
        } catch (Exception e) {  
            throw new RuntimeException(e);  
        }  

    }

}