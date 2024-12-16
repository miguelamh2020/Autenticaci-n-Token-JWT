package com.authentication.jwttokenauthentication.security;

import com.authentication.jwttokenauthentication.constants.Constants;
import com.authentication.jwttokenauthentication.model.JwtAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JwtAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

	public JwtAuthenticationTokenFilter() {
		super("/api/**");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		try {
			String header = request.getHeader(Constants.AUTHORIZATION_HEADER);
			if (header == null || !header.startsWith(Constants.BEARER_TOKEN)) {
				sendErrorResponse(response, "InvalidToken", "El token es inválido o no fue enviado.");
				return null; // Detener aquí
			}

			String authenticationToken = header.substring(7);
			JwtAuthenticationToken token = new JwtAuthenticationToken(authenticationToken);
			return getAuthenticationManager().authenticate(token);

		} catch (RuntimeException e) {
			if (e.getMessage().equals("Token expirado")) {
				sendErrorResponse(response, "TokenExpired", "El token ha expirado. Por favor, inicie sesión nuevamente.");
			} else {
				sendErrorResponse(response, "InvalidToken", "El token es inválido.");
			}
			return null; // Detener el flujo
		}
	}

	private void sendErrorResponse(HttpServletResponse response, String error, String message) throws IOException {
		response.setContentType("application/json");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

		Map<String, String> errorResponse = new HashMap<>();
		errorResponse.put("error", error);
		errorResponse.put("message", message);

		ObjectMapper mapper = new ObjectMapper();
		response.getWriter().write(mapper.writeValueAsString(errorResponse));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
											Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		chain.doFilter(request, response);
	}
}
