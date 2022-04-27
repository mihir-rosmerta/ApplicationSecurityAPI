package com.integrate.app.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter{

	@Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
	
	@Autowired
	private JwtRequestFilter jwtRequestFilter;
	
	@Autowired
	private PasswordEncoder bcryptPasswordEncoder;
	
	@Autowired
	private PasswordEncoder md5PasswordEncoder;
	
	@Autowired
	private PasswordEncoder sha1PasswordEncoder;
	
	@Autowired
	private PasswordEncoder sha256PasswordEncoder;
	
	@Autowired
	private PasswordEncoder sha512PasswordEncoder;
	
	@Autowired
	private PasswordEncoder pbkdf2PasswordEncoder;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().passwordEncoder(bcryptPasswordEncoder)
			.withUser("user1").password(bcryptPasswordEncoder.encode("user1pass")).roles("USER");
		auth.inMemoryAuthentication().passwordEncoder(md5PasswordEncoder)
			.withUser("user2").password(md5PasswordEncoder.encode("user2pass")).roles("USER");
		auth.inMemoryAuthentication().passwordEncoder(sha1PasswordEncoder)
			.withUser("user3").password(sha1PasswordEncoder.encode("user3pass")).roles("USER");
		auth.inMemoryAuthentication().passwordEncoder(sha256PasswordEncoder)
			.withUser("user4").password(sha256PasswordEncoder.encode("user4pass")).roles("USER");
		auth.inMemoryAuthentication().passwordEncoder(sha512PasswordEncoder)
			.withUser("user5").password(sha512PasswordEncoder.encode("user5pass")).roles("USER");
		auth.inMemoryAuthentication().passwordEncoder(pbkdf2PasswordEncoder)
			.withUser("user6").password(pbkdf2PasswordEncoder.encode("user6pass")).roles("USER");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
			.authorizeRequests()
			.antMatchers("/api/v1/authenticate").permitAll()
			.anyRequest().authenticated().and()
			.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

	}

	
}
