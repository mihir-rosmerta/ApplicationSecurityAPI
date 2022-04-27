package com.integrate.app.auth.payloads;

import lombok.Data;

@Data
public class AuthenticationRequest {

	String username;
	String password;
}
