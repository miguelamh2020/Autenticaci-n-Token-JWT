package com.authentication.jwttokenauthentication.security;

import com.authentication.jwttokenauthentication.model.JwtAuthenticationToken;
import com.authentication.jwttokenauthentication.model.JwtUser;
import com.authentication.jwttokenauthentication.model.JwtUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

	@Autowired
	private JwtValidator validator;

	@Override
	protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {

		JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
		String token = jwtAuthenticationToken.getToken();
		JwtUser jwtUser;

		try {
			jwtUser = validator.validate(token);
		} catch (RuntimeException e) {
			throw new AuthenticationException(e.getMessage()) {};
		}

		List<GrantedAuthority> grantedAuthorities = AuthorityUtils
				.commaSeparatedStringToAuthorityList(jwtUser.getRole());

		return new JwtUserDetails(jwtUser.getUserName(), jwtUser.getId(), token, grantedAuthorities);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
	}

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
												  UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		// No necesitamos lógica aquí
	}
}
