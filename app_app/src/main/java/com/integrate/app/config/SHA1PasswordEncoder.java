package com.integrate.app.config;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.security.crypto.password.PasswordEncoder;

public class SHA1PasswordEncoder implements PasswordEncoder{
	
	private String salt;
	
	public SHA1PasswordEncoder(String salt) {
		super();
		this.salt = salt;
	}

	public String sha1(String input, String salt) {
		String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(salt.getBytes());
            byte[] bytes = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16)
                        .substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
	}

	@Override
	public String encode(CharSequence rawPassword) {
		return sha1(rawPassword.toString(),salt);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return sha1(rawPassword.toString(),salt).equals(encodedPassword);
	}
}
