package com.bugbycode.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
        .requestMatchers().antMatchers("/oauth/**","/login/**","/logout/**")
        .and()
        .authorizeRequests().antMatchers("/imgCode").permitAll()
        .antMatchers("/oauth/**").authenticated()
        .and()
        .formLogin().loginPage("/login").permitAll();
	}
	
}