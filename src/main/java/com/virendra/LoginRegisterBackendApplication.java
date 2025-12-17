package com.virendra;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;


@SpringBootApplication
	    
	
public class LoginRegisterBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(LoginRegisterBackendApplication.class, args);
	}

}
