package com.authentication.jwttokenauthentication.security;

import com.authentication.jwttokenauthentication.constants.Constants;
import com.authentication.jwttokenauthentication.model.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Component
public class JwtGenerator {

	public String generate(JwtUser jwtUser) {
		String tokenId = UUID.randomUUID().toString(); // Generar un identificador único para el token

		// Establecer el tiempo de expiración (ejemplo: 1 hora)
		long expirationTime = 60000; // 1 min en milisegundos
		Date issuedAt = new Date();
		Date expirationDate = new Date(issuedAt.getTime() + expirationTime);

		Claims claims = Jwts.claims()
				.setSubject(jwtUser.getUserName())
				.setId(tokenId)
				.setIssuedAt(issuedAt)/*Retirar si no quiere q haya tiempo de expiracion*/
				.setExpiration(expirationDate);/*Retirar si no quiere q haya tiempo de expiracion*/

		claims.put(Constants.USER_ID, String.valueOf(jwtUser.getId()));
		claims.put(Constants.ROLE, jwtUser.getRole());

		return Jwts.builder()
				.setClaims(claims)
				.signWith(SignatureAlgorithm.HS256, Constants.YOUR_SECRET)
				.compact();
	}
}
