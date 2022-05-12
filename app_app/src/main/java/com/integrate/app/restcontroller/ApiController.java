package com.integrate.app.restcontroller;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.integrate.app.auth.payloads.AuthenticationRequest;
import com.integrate.app.auth.payloads.AuthenticationResponse;
import com.integrate.app.config.HmacSha1PasswordEncoder;
import com.integrate.app.config.JwtUtil;
import com.integrate.app.config.MyUserDetailsService;
import com.integrate.app.model.User;
import com.integrate.app.model.UserDetailsImpl;
import com.integrate.app.restservice.ApiService;

@RestController
@RequestMapping("/api/v1")
public class ApiController {

	@Autowired
	AuthenticationManager authenticationManagerBean;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private MyUserDetailsService userDetailsService;
	
	@Autowired
	private ApiService apiService;
	
	@Autowired
	private HmacSha1PasswordEncoder hmacSha1PasswordEncoder;
	
	public static String userKey = "$px`h";
	
	@PostMapping("/authenticate-with-dynamic-key")
	public String handshake(@RequestHeader("accept-key") String auth, Principal principal) {
		User user = null;
		if(principal != null) {
			user = userDetailsService.loadUserByUsername(principal.getName()).getUser();
		}
		if(user != null && auth.equals(apiService.decrypt(user.getKey()))) {
			return "Authenticated with Dynamic Key";
		}
		return "Invalid Key!";
		
	}
	
	@PostMapping("/testing")
	public ResponseEntity<?> testing(Principal principal){
		if(principal != null) {
			User user = userDetailsService.loadUserByUsername(principal.getName()).getUser();
			return ResponseEntity.ok(user);
		}
		return ResponseEntity.ok("Invalid User!");
	}
	
	@PostMapping(value="/auth2", consumes = "text/plain")
	public ResponseEntity<?> authenticate2(@RequestBody String auth){
		byte[] credDecoded = Base64.getDecoder().decode(auth);
		String credentials = new String(credDecoded, StandardCharsets.UTF_8);
		final String[] values = credentials.split(":", 2);
		String username = values[0];
		String password = values[1];
		String encodedPassword = hmacSha1PasswordEncoder.encode(password);
		AuthenticationRequest authenticationRequest = new AuthenticationRequest();
		authenticationRequest.setUsername(username);
		authenticationRequest.setPassword(encodedPassword);
		return authenticate3(authenticationRequest);
	}
	

	@PostMapping(value="/alternateauth2", consumes = "text/plain")
	public ResponseEntity<?> alternateauth2(@RequestBody String auth) {
		String decryptedString = "";
		String keyString = auth.substring(0, 16);
	    String ivString = auth.substring(16, 32);
	    String additionalString = auth.substring(32, 56);
	    String cipherString = auth.substring(56); 
	    
	    byte[] keyBytes = keyString.getBytes();
	    SecretKey key = new SecretKeySpec(keyBytes, "AES");
	    byte[] ivBytes = ivString.getBytes();

	    byte[] one = Base64.getDecoder().decode(cipherString);
	    byte[] two = Base64.getDecoder().decode(additionalString);
	    byte[] cipherText = new byte[one.length + two.length];
	    System.arraycopy(one, 0, cipherText, 0, one.length);
	    System.arraycopy(two, 0, cipherText, one.length, two.length);
	    try {
			decryptedString = ApiService.decrypt(cipherText, key, ivBytes);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		String username = decryptedString.split(":")[0];
		String password = decryptedString.split(":")[1];
		String encodedPassword = hmacSha1PasswordEncoder.encode(password);
		AuthenticationRequest authenticationRequest = new AuthenticationRequest();
		authenticationRequest.setUsername(username);
		authenticationRequest.setPassword(encodedPassword);
		return authenticate3(authenticationRequest);
	}
	
	@PostMapping("/auth3")
	public ResponseEntity<?> authenticate3(@RequestBody AuthenticationRequest authenticationRequest){
		String password = authenticationRequest.getPassword();
		String username = authenticationRequest.getUsername();
		UserDetailsImpl userDetails = this.userDetailsService.loadUserByUsername(username);
		if(userDetails != null && password.equals(userDetails.getUser().getPassword())) {
			return ResponseEntity.ok("Login Successfull!!");
		}
		return ResponseEntity.ok("Login Failed!!");
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest authenticationRequest){
		Authentication authentication = authenticationManagerBean.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(authentication.getName());
        final String jwt = jwtUtil.generateToken(userDetails);
        User user = userDetails.getUser();
		return ResponseEntity.ok(new AuthenticationResponse("Bearer",jwt,user));
		
	}
	
}
