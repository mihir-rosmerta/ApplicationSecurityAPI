package com.integrate.app.config;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.integrate.app.model.User;
import com.integrate.app.model.UserDetailsImpl;

public class MyUserDetailsService implements UserDetailsService{

	
	public static User user1 = null;
	public static User user2 = null;
	public static User user3 = null;
	public static User user4 = null;
	public static User user5 = null;
	public static User user6 = null;
	
	
	@Override
	public UserDetailsImpl loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetailsImpl userDetails = null;
		if(username.equals("user1")) {
			userDetails = new UserDetailsImpl(user1);
		}
		if(username.equals("user2")) {
			userDetails = new UserDetailsImpl(user2);
		}
		if(username.equals("user3")) {
			userDetails = new UserDetailsImpl(user3);
		}
		if(username.equals("user4")) {
			userDetails = new UserDetailsImpl(user4);
		}
		if(username.equals("user5")) {
			userDetails = new UserDetailsImpl(user5);
		}
		if(username.equals("user6")) {
			userDetails = new UserDetailsImpl(user6);
		}
		if(userDetails == null)throw new UsernameNotFoundException("Could not find user!");
		return userDetails;
	}

}
