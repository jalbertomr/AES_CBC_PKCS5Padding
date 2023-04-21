import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class AES_CBC_PKCS5Padding {
	private static final String key128 = "aesEncryptionKey"; // valid for 128, 16 Characteres * 8 = 128bits
	private static final String key256 = "aesEncryptionKeyaesEncryptionKey"; //valid for 256, 32 characteres * 8 = 256bits
	//private static final String key = "12345678901234567890123456789012";
	private static final String initVector128 = "encryptionIntVec";	
	private static final String initVector256 = "encryptionIntVecencryptionIntVec";	//Not valid should be 128bits
	
  public static void main(String... args) {
	   String originalString = "MensajeAEncriptarCon128AESCBCPKCS5Padding";
	    System.out.println("Original String to encrypt - " + originalString);
	    String encryptedString = encrypt128(originalString);
	    System.out.println("Encrypted String - " + encryptedString);
	    String decryptedString = decrypt128(encryptedString);
	    System.out.println("After decryption - " + decryptedString);
		originalString = "MensajeAEncriptarCon256AESCBCPKCS5Padding";
		    System.out.println("Original String to encrypt - " + originalString);
		    encryptedString = encrypt256(originalString);
		    System.out.println("Encrypted String - " + encryptedString);
		    decryptedString = decrypt256(encryptedString);
		    System.out.println("After decryption - " + decryptedString);

	    System.out.println("---- Sin IV ----");
	    System.out.println("Original String to encrypt - " + originalString);
	    encryptedString = encryptWithoutIv(originalString);
	    System.out.println("Encrypted String - " + encryptedString);
	    decryptedString = decryptWithoutIv(encryptedString);
	    System.out.println("After decryption - " + decryptedString);

  }
  
  public static String encrypt128(String value) {
	    try {
	        IvParameterSpec iv = new IvParameterSpec(initVector128.getBytes("UTF-8"));
	        SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");
	 
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
	        
	        byte[] encrypted = cipher.doFinal(value.getBytes());
	        return Base64.getEncoder().encodeToString(encrypted);
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	    return null;
	}
  
  public static String decrypt128(String encrypted) {
	    try {
	        IvParameterSpec iv = new IvParameterSpec(initVector128.getBytes("UTF-8"));
	        SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");
	 
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
	        
	        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
	        return new String(original);
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	 
	    return null;
	}

  public static String encrypt256(String value) {
	    try {
	        IvParameterSpec iv = new IvParameterSpec(initVector128.getBytes("UTF-8"));
	        SecretKeySpec skeySpec = new SecretKeySpec(key256.getBytes("UTF-8"), "AES");
	 
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
	        
	        byte[] encrypted = cipher.doFinal(value.getBytes());
	        return Base64.getEncoder().encodeToString(encrypted);
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	    return null;
	}

public static String decrypt256(String encrypted) {
	    try {
	        IvParameterSpec iv = new IvParameterSpec(initVector128.getBytes("UTF-8"));
	        SecretKeySpec skeySpec = new SecretKeySpec(key256.getBytes("UTF-8"), "AES");
	 
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
	        
	        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
	        return new String(original);
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	 
	    return null;
	}

  public static String encryptWithoutIv(String value) {
	    try {
	        IvParameterSpec iv = new IvParameterSpec(key128.getBytes("UTF-8"));
	        SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");
	 
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
	        
	        byte[] encrypted = cipher.doFinal(value.getBytes());
	        return Base64.getEncoder().encodeToString(encrypted);
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	    return null;
	}

public static String decryptWithoutIv(String encrypted) {
	    try {
	        IvParameterSpec iv = new IvParameterSpec(key128.getBytes("UTF-8"));
	        SecretKeySpec skeySpec = new SecretKeySpec(key128.getBytes("UTF-8"), "AES");
	 
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
	        
	        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
	        return new String(original);
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	 
	    return null;
	}

}

