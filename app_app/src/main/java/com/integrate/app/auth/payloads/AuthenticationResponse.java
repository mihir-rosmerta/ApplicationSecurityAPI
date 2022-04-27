package com.integrate.app.auth.payloads;

import com.integrate.app.model.User;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthenticationResponse {
	private String tokenType;
	private String jwt;
	private User user;
}
