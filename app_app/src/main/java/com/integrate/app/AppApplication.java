package com.integrate.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.integrate.app.restservice.ApiService;

@SpringBootApplication
public class AppApplication {

	public static void main(String[] args) {
		ApiService apiService = new ApiService();
		apiService.createUsers();
		SpringApplication.run(AppApplication.class, args);
	}

}
