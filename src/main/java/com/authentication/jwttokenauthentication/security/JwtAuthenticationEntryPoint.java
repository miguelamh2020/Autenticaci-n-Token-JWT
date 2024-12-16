package com.authentication.jwttokenauthentication.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
						 AuthenticationException authException) throws IOException {

		response.setContentType("application/json");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

		String errorMessage = authException.getMessage();

		Map<String, String> errorResponse = new HashMap<>();
		if ("Token expirado".equals(errorMessage)) {
			errorResponse.put("error", "TokenExpired");
			errorResponse.put("message", "El token ha expirado. Por favor, inicie sesión nuevamente.");
		} else if ("Token inválido".equals(errorMessage) || "Token inválido o no presente".equals(errorMessage)) {
			errorResponse.put("error", "InvalidToken");
			errorResponse.put("message", "El token es inválido o no fue enviado.");
		} else {
			errorResponse.put("error", "Unauthorized");
			errorResponse.put("message", "No autorizado.");
		}

		new ObjectMapper().writeValue(response.getWriter(), errorResponse);
	}

}
