package com.integrate.app.restservice;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.stereotype.Service;

import com.integrate.app.config.HmacSha1PasswordEncoder;
import com.integrate.app.config.MD5PasswordEncoder;
import com.integrate.app.config.MyUserDetailsService;
import com.integrate.app.config.SHA1PasswordEncoder;
import com.integrate.app.config.SHA256PasswordEncoder;
import com.integrate.app.config.SHA512PasswordEncoder;
import com.integrate.app.model.User;
import com.integrate.app.restcontroller.ApiController;

@Service
public class ApiService {
	
	private String salt = getSalt();
	public String encrypt(String dynamicKey) {
		String str = "";
		for(char ch: dynamicKey.toCharArray()) {
			int ascii = (int)ch;
			str = str + String.valueOf(ascii);
		}
		System.out.println("Joined ASCII = "+str);
		BigInteger num = new BigInteger(str);
		System.out.println("num = "+num);
		double log = Math.log10(num.doubleValue());
		System.out.println("after log = "+ log);
		double sine = Math.sin(Math.toRadians(log));
		System.out.println("after sine = "+ sine);
		String res = String.valueOf(sine);
		res = res.substring(2)+"1";
		return res;
	}
	//^az|f to 
	//224569967854564261
	
	public String decrypt(String encryptedKey) {
		encryptedKey = encryptedKey.substring(0,encryptedKey.length()-1);
		BigInteger num = new BigInteger(encryptedKey);
		System.out.println("after removing last digit 1 = "+num.toString());
		double value = 0;
		String ans = "0."+num.toString();
		System.out.println("After dividing by power of 10 = "+ans);
		BigDecimal bd = new BigDecimal(ans);
		System.out.println(bd.doubleValue());
		value = Math.asin(bd.doubleValue());
		value = Math.toDegrees(value);
		System.out.println("After sine inverse = "+value);
		value = Math.pow(10, value);
		System.out.println("after anti-log = "+value);
		String ascii = String.valueOf(value).substring(0,1)+String.valueOf(value).substring(2,14);
	    System.out.println("Final ASCII = "+ascii);
	    
		String res = "";
		int i = 0;
	    while(i < ascii.length()-2) {
	    	String temp = ascii.charAt(i)+""+ascii.charAt(i+1);
	    	char ch;
	    	if(Integer.parseInt(temp)>33) {ch = (char)Integer.parseInt(temp);i+=2;}
	    	else {temp+=ascii.charAt(i+2);ch = (char)Integer.parseInt(temp);i+=3;}
	    	res = res + ch;
	    }
		return res;
	}
	
	private String getSalt() {
        SecureRandom sr = null;
        try {
			sr = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt.toString();
    }
	
	public static String decrypt(byte[] cipherText, SecretKey key, byte[] IV) throws Exception {
	    // Get Cipher Instance
	    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

	    // Create SecretKeySpec
	    SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

	    // Create GCMParameterSpec
	    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128 , IV);

	    // Initialize Cipher for DECRYPT_MODE
	    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

	    cipher.updateAAD("nvn".getBytes());
	    byte[] decryptedText = cipher.doFinal(cipherText);

	    return new String(decryptedText);
	} 
	
	
	@Bean
	public MyUserDetailsService userDetailsService() {
		return new MyUserDetailsService();
	}
	
	@Bean
	public PasswordEncoder bcryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public PasswordEncoder md5PasswordEncoder() {
		return new MD5PasswordEncoder(salt);
	}
	
	@Bean
	public PasswordEncoder sha1PasswordEncoder() {
		return new SHA1PasswordEncoder(salt);
	}
	
	@Bean
	public PasswordEncoder sha256PasswordEncoder() {
		return new SHA256PasswordEncoder(salt);
	}
	
	@Bean
	public PasswordEncoder sha512PasswordEncoder() {
		return new SHA512PasswordEncoder(salt);
	}
	
	@Bean
	public PasswordEncoder pbkdf2PasswordEncoder() {
		return new Pbkdf2PasswordEncoder();
	}

	@Bean
	public PasswordEncoder hmacSha1PasswordEncoder() {
		return new HmacSha1PasswordEncoder(); 
	}
	
	public void createUsers() {
		MyUserDetailsService.user1 = new User();
		MyUserDetailsService.user1.setUsername("user1");
		MyUserDetailsService.user1.setPassword(bcryptPasswordEncoder().encode("user1pass"));
		MyUserDetailsService.user1.setKey(encrypt("$px`h"));
		MyUserDetailsService.user2 = new User();
		MyUserDetailsService.user2.setUsername("user2");
		MyUserDetailsService.user2.setPassword(md5PasswordEncoder().encode("user2pass"));
		MyUserDetailsService.user2.setKey(encrypt("^az|f"));
		MyUserDetailsService.user3 = new User();
		MyUserDetailsService.user3.setUsername("user3");
		MyUserDetailsService.user3.setPassword(sha1PasswordEncoder().encode("user3pass"));
		MyUserDetailsService.user3.setKey(encrypt(ApiController.userKey));
		MyUserDetailsService.user4 = new User();
		MyUserDetailsService.user4.setUsername("user4");
		MyUserDetailsService.user4.setPassword(sha256PasswordEncoder().encode("user4pass"));
		MyUserDetailsService.user4.setKey(encrypt(ApiController.userKey));
		MyUserDetailsService.user5 = new User();
		MyUserDetailsService.user5.setUsername("user5");
		MyUserDetailsService.user5.setPassword(sha512PasswordEncoder().encode("user5pass"));
		MyUserDetailsService.user5.setKey(encrypt(ApiController.userKey));
		MyUserDetailsService.user6 = new User();
		MyUserDetailsService.user6.setUsername("user6");
		MyUserDetailsService.user6.setPassword(pbkdf2PasswordEncoder().encode("user6pass"));
		MyUserDetailsService.user6.setKey(encrypt(ApiController.userKey));
		MyUserDetailsService.user7 = new User();
		MyUserDetailsService.user7.setUsername("user7");
		MyUserDetailsService.user7.setPassword(hmacSha1PasswordEncoder().encode("user7pass"));
		MyUserDetailsService.user7.setKey(encrypt(")od%3"));
		
	}
	
}
