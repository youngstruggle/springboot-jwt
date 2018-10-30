package com.springboot.jwt.security.demo.service;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.springboot.jwt.security.demo.model.ApplicationUser;

@Component
public class CustomUserDetailsService implements UserDetailsService {
		
	/*@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		return new User("batman","{noop}pass",AuthorityUtils.createAuthorityList("ROLE_USER"));
		
		// Kenapa harus ditambahkan {noop} 
		// https://stackoverflow.com/questions/46999940/spring-boot-passwordencoder-error 
	}*/
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		ApplicationUser applicationUser = loadApplicationUserByUsername(username);
		return new User(applicationUser.getUsername(),"{noop}" + applicationUser.getPassword(),AuthorityUtils.createAuthorityList("ROLE_USER"));
	}
	
	public ApplicationUser loadApplicationUserByUsername(String username) {
		return new ApplicationUser("batman", "pass");
	}

}
