package com.integrate.app.config;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.password.PasswordEncoder;

public class HmacSha1PasswordEncoder implements PasswordEncoder{

	private final static char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
	
	String key = "knaqrbphwer6543";
	
	public byte[] sha1Hmac(String data, String key)
	{
	    byte[] res=null;
			SecretKey signingKey = new SecretKeySpec(key.getBytes(), "HMACSHA1");  
			Mac mac;
			try {
				mac = Mac.getInstance("HMACSHA1");
				mac.init(signingKey);
				res = mac.doFinal(data.getBytes("UTF-8"));
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalStateException | UnsupportedEncodingException e) {
				e.printStackTrace();
			} 
			
			return res;
	}       

	public String encode(byte[] buf){
        int size = buf.length;
        char[] ar = new char[((size + 2) / 3) * 4];
        int a = 0;
        int i=0;
        while(i < size)
		{
            byte b0 = buf[i++];
            byte b1 = (i < size) ? buf[i++] : 0;
            byte b2 = (i < size) ? buf[i++] : 0;

            int mask = 0x3F;
            ar[a++] = ALPHABET[(b0 >> 2) & mask];
            ar[a++] = ALPHABET[((b0 << 4) | ((b1 & 0xFF) >> 4)) & mask];
            ar[a++] = ALPHABET[((b1 << 2) | ((b2 & 0xFF) >> 6)) & mask];
            ar[a++] = ALPHABET[b2 & mask];
        }
        switch(size % 3)
		{
            case 1: ar[--a]  = '=';
            case 2: ar[--a]  = '=';
        }
        return new String(ar);
    }

	@Override
	public String encode(CharSequence rawPassword) {
		return encode(sha1Hmac(rawPassword.toString(),key));
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return encode(sha1Hmac(rawPassword.toString(),key)).equals(encodedPassword);
	}

}
