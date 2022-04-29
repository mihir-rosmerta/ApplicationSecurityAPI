package com.integrate.app.restcontroller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.integrate.app.auth.payloads.AuthenticationRequest;
import com.integrate.app.auth.payloads.AuthenticationResponse;
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
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest authenticationRequest){
		Authentication authentication = authenticationManagerBean.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(authentication.getName());
        final String jwt = jwtUtil.generateToken(userDetails);
        User user = userDetails.getUser();
		return ResponseEntity.ok(new AuthenticationResponse("Bearer",jwt,userDetails.getUser()));
		
	}
	
}
