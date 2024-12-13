package com.authentication.jwttokenauthentication.security;

import com.authentication.jwttokenauthentication.constants.Constants;
import com.authentication.jwttokenauthentication.model.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

@Component
public class JwtValidator {

	public JwtUser validate(String token) {
		JwtUser jwtUser = null;
		
		try {
			Claims body = Jwts.parser()
					.setSigningKey(Constants.YOUR_SECRET)
					.parseClaimsJws(token)
					.getBody();
			
			jwtUser = new JwtUser();
			jwtUser.setUserName(body.getSubject());
			jwtUser.setId(Long.parseLong((String) body.get(Constants.USER_ID)));
			jwtUser.setRole((String) body.get(Constants.ROLE));
			
		}catch(Exception e) {
			System.out.println(e);
		}
		
		return jwtUser;
	}
	
}
