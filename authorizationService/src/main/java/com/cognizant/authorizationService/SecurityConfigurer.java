package com.cognizant.authorizationService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import com.cognizant.authorizationService.service.AdminDetailsService;

@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {
	//websecurity'sfunctions we can override like configure and get ->alt enter n httpsecurity
	private static Logger logger = LoggerFactory.getLogger(SecurityConfigurer.class);

	@Autowired
	//make bean for the pass/username and using loadby function later
	AdminDetailsService pmsuserDetailsService;

	@Override
	//authentication manager will give like which type of authentication is to be given/applied.
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		logger.info("SecurityConfigurer.configure.STARING AUTH SECURITY CONFIGURE");
		super.configure(auth);
		auth.userDetailsService(pmsuserDetailsService);
		logger.info("SecurityConfigurer.configure.END AUTH SECURITY CONFIGURE AUTH");
	}

	@Override
	// below for allowing http link ,authenticate which links to be allowed
	protected void configure(HttpSecurity http) throws Exception {
		logger.info("SecurityConfigurer.configure.STARING HTTP SECURITY CONFIGURE");
		http.csrf().disable().authorizeRequests().antMatchers("/**").permitAll().anyRequest().authenticated().and()
				.exceptionHandling().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		logger.info("SecurityConfigurer.configure.ENDDING HTTP SECURITY CONFIGURE");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		logger.info("SecurityConfigurer.configure.STARTING WEB SECURITY");

		web.ignoring().antMatchers("/authapp/login", "/h2-console/**", "/v2/api-docs", "/configuration/ui",
				"/configuration/security", "/webjars/**");
		logger.info("SecurityConfigurer.configure.ENDING WEB SECURITY");
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
