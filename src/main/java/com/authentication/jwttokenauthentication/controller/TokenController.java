package com.authentication.jwttokenauthentication.controller;

import com.authentication.jwttokenauthentication.model.JwtUser;
import com.authentication.jwttokenauthentication.model.Login;
import com.authentication.jwttokenauthentication.model.UserToken;
import com.authentication.jwttokenauthentication.repository.TokenRepository;
import com.authentication.jwttokenauthentication.security.JwtGenerator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/token")
public class TokenController {

	private final JwtGenerator jwtGenerator;
	private final TokenRepository tokenRepository;

	public TokenController(JwtGenerator jwtGenerator, TokenRepository tokenRepository) {
		this.jwtGenerator = jwtGenerator;
		this.tokenRepository = tokenRepository;
	}

	@PostMapping
	public ResponseEntity<?> generate(@RequestBody final Login login) {
		JwtUser jwtUser = existUser(login);
		if (jwtUser != null) {
			String token = jwtGenerator.generate(jwtUser);

			// Guardar el token en la base de datos
			UserToken userToken = new UserToken();
			userToken.setUserId(jwtUser.getId());
			userToken.setToken(token);
			tokenRepository.save(userToken);

			List<String> lista = new ArrayList<>();
			lista.add(token);
			return new ResponseEntity<>(lista, HttpStatus.OK);
		} else {
			return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
		}
	}

	private JwtUser existUser(Login login) {
		if (login.getUser().equals("alberto") && login.getPassword().equals("1234")) {
			JwtUser jwtUser = new JwtUser();
			jwtUser.setUserName(login.getUser());
			jwtUser.setId(1L);
			jwtUser.setRole("Admin");
			return jwtUser;

		} else {
			return null;
		}
	}
}
