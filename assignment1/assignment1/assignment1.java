package assignment1;
import java.security.MessageDigest;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.util.Random;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;


public class assignment1 {

	public static void main(String[] args) {
		
		byte[] Kmac = new byte[16];
		Arrays.fill(Kmac, (byte)0x0b);
		
		byte[] Kenc = new byte[16];
		Arrays.fill(Kenc, (byte)0x01);
		
		String m = "Hi There";
		byte[] Message = m.getBytes();
		
		Encrypt(Kenc, Kmac, Message);
		
	}

	private static byte[] Encrypt(byte[] Kenc, byte[] Kmac, byte[] Message){
		byte[] HMAC = Sha1Mac(Kmac, Message);
		byte[] messageX = concat(Message, HMAC);
		byte[] messageXX = concat(messageX, Pkcs(messageX));
		
		byte[] IV = new byte[16];
		Arrays.fill(IV, (byte)0x00);
		//new Random().nextBytes(IV);
		
		byte[] cipherText = CbcAes(Kenc, IV, messageXX);
		for (int i = 0; i < cipherText.length; i ++) {
			System.out.print(String.format("%02x", cipherText[i]));
		}
		return cipherText;
	}
	
	private static byte[] CbcAes(byte[] Kenc, byte[] IV, byte[] messageXX) {
	    SecretKey key = new SecretKeySpec(Kenc, 0, Kenc.length, "AES");
	    Cipher aes = null;
	    try {
	    	aes = Cipher.getInstance("AES");
	    	aes.init(aes.ENCRYPT_MODE, key);
	    } catch (Exception e){
	    	e.printStackTrace();
	    }
	    
	    byte[] cipherText = null;
	    byte[] currCipher = null;
	    for (int i = 0; i < (messageXX.length / 16); i++){
	    	byte[] currBlock = Arrays.copyOfRange(messageXX, i * 16, (i + 1) * 16);
	    	if (i == 0) {
	    		currBlock = XorRA(currBlock, IV, 16);
	    	} else {
	    		currBlock = XorRA(currBlock, currCipher, 16);
	    	}
	    	try {
	    		currCipher = aes.doFinal(currBlock);
	    		cipherText = concat(cipherText, currCipher);
	    	} catch (Exception e) {
	    		e.printStackTrace();
	    	}
	    }
	    return cipherText;
	}
	

	private static byte[] Pkcs(byte[] messageX) {
		byte[] ps;
		int n = messageX.length % 16;
		if (n == 0) {
			ps = new byte[16];
			Arrays.fill(ps, (byte)0x10);
		} else {
			ps = new byte[16 - n];
			Arrays.fill(ps, (byte)(16-n));
		}
		return ps;
	}
	
	private static byte[] Sha1Mac(byte[] Kmac, byte[] Message) {
		//Create Padded Key
		byte[] padding = new byte[48];
		byte[] paddedKey = concat(Kmac, padding);

		//Create Opad
		byte[] opad = new byte[64];
		Arrays.fill(opad, (byte)0x5c);
		
		//Create Ipad
		byte[] ipad = new byte[64];
		Arrays.fill(ipad, (byte)0x36);
		
		//Create the terms for the HMAC
		//Term 1
		byte[] term1 = XorRA(paddedKey, opad, 64);

		//Term 2
		//This code taken from stack overflow http://stackoverflow.com/questions/4895523/java-string-to-sha1
	    MessageDigest md = null;
	    try {
	        md = MessageDigest.getInstance("SHA-1");
	    }
	    catch(Exception e) {
	        e.printStackTrace();
	    } 
		byte[] term2 = XorRA(paddedKey, ipad, 64);
		term2 = concat(term2, Message);
		md.reset();
		md.update(term2);
		term2 = md.digest();
		
		//Final hash
		//Full expression before hash
		byte[] MAC = concat(term1, term2);
		md.reset();
		md.update(MAC);
		MAC = md.digest();
		
		return MAC;
	}
	
	private static byte[] XorRA(byte[] a, byte[] b, int length) {
		byte[] ra = new byte[length];
		for (int i = 0; i < length; i++) {
			ra[i] = (byte)((int)a[i] ^ (int)b[i]);
		}
		return ra;
	}
	
	private static byte[] concat(byte[] a, byte[] b) {
		if (a == null) {
			return b;
		}
		int total = a.length + b.length;
		byte[] c = new byte[total];
		for (int i = 0; i < total; i++) {
			if (i < a.length) {
				c[i] = a[i];
			} else {
				c[i] = b[i- a.length];
			}
		}
		return c;
	}
}
