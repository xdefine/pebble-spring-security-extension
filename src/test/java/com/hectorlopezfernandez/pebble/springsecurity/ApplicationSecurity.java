package com.hectorlopezfernandez.pebble.springsecurity;

import java.util.Properties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// general properties
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
		// login config
		http.httpBasic();
		// access rules
		http.authorizeRequests().anyRequest().permitAll();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		Properties users = new Properties();
		users.put("admin","admin,ROLE_ADMIN,enabled");
		users.put("user","user,ROLE_USER,enabled");
		return new InMemoryUserDetailsManager(users);
	}

}