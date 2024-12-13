package com.authentication.jwttokenauthentication.security;


import com.authentication.jwttokenauthentication.constants.Constants;
import com.authentication.jwttokenauthentication.model.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

@Component
public class JwtGenerator {
	public String generate(JwtUser jwtUser) {
		Claims claims = Jwts.claims()
				.setSubject(jwtUser.getUserName());
		claims.put(Constants.USER_ID, String.valueOf(jwtUser.getId()));
		claims.put(Constants.ROLE, jwtUser.getRole());
		
		return Jwts.builder()
				.setClaims(claims)
				.signWith(SignatureAlgorithm.HS256, Constants.YOUR_SECRET)
				.compact();
		
	}
}
