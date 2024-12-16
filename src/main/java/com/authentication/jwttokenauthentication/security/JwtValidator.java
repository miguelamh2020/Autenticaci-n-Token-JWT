package com.authentication.jwttokenauthentication.security;

import com.authentication.jwttokenauthentication.constants.Constants;
import com.authentication.jwttokenauthentication.model.JwtUser;
import com.authentication.jwttokenauthentication.model.UserToken;
import com.authentication.jwttokenauthentication.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class JwtValidator {

	@Autowired
	private TokenRepository tokenRepository;

	public JwtUser validate(String token) {
		JwtUser jwtUser;

		try {
			Claims body = Jwts.parser()
					.setSigningKey(Constants.YOUR_SECRET)
					.parseClaimsJws(token)
					.getBody();

			Long userId = Long.parseLong((String) body.get(Constants.USER_ID));
			UserToken storedToken = tokenRepository.findByUserId(userId);

			if (storedToken == null || !storedToken.getToken().equals(token)) {
				throw new RuntimeException("Token inválido");
			}
			System.out.println("Token recibido: " + token);
			jwtUser = new JwtUser();
			jwtUser.setUserName(body.getSubject());
			jwtUser.setId(userId);
			jwtUser.setRole((String) body.get(Constants.ROLE));

		} catch (ExpiredJwtException e) {
			throw new JwtAuthenticationException("Token expirado");
		} catch (Exception e) {
			throw new JwtAuthenticationException("Token inválido");
		}


		return jwtUser;
	}
}
