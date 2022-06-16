package com.cognizant.authorizationService.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtil {
	private static Logger logger = LoggerFactory.getLogger(JwtUtil.class);
	/**
	 * creating a secret key for token, can be changed to anything ,has methids to
	 * genereting,validating tojken,//issexpired.
	 */
	private String secretkey = "${jwt.secret}";
	private String secret;

	private static final long JWT_Token_validity = 5 * 60 * 60;
	private int refreshExpirationDateInMs = 900000;

	/**
	 * This method is used to extract the username from the token
	 * 
	 * @param token in the string format
	 * @return
	 */
	public String extractUsername(String token) {

		return extractClaim(token, Claims::getSubject);

	}

	/**
	 * This method is used to extract a particular claim for the token
	 * 
	 * @param <T>
	 * @param token
	 * @param claimsResolver
	 * @return
	 */
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		logger.info("JwtUtil.extractClaim.authorizationservice.extractClaim.START the token");

		final Claims claims = extractAllClaims(token);
		logger.info("END");

		return claimsResolver.apply(claims);

	}

	/**
	 * This method is used to extract claims for the token
	 * 
	 * @param token
	 * @return
	 */
	private Claims extractAllClaims(String token) {

		return Jwts.parser().setSigningKey(secretkey).parseClaimsJws(token).getBody();

	}

	public String generateToken(UserDetails userDetails) {
		logger.info("JwtUtil.generateToken.START GENERATING TOKEN");

		Map<String, Object> claims = new HashMap<>();
		logger.info("JwtUtil.generateToken.ENDING GENERATING TOKEN");

		return createToken(claims, userDetails.getUsername());
	}

	/**
	 * This method is used to create token based on the claims and subject given as
	 * parameter. It will add a signature to the jwt token based on the algorithm
	 * HS256.
	 * 
	 * @param claims
	 * @param subject
	 * @return
	 */
	private String createToken(Map<String, Object> claims, String subject) {
		logger.info("JwtUtil.createToken.START");

		String compact = Jwts.builder().setClaims(claims).setSubject(subject)
				.setIssuedAt(new Date(System.currentTimeMillis())).signWith(SignatureAlgorithm.HS256, secretkey)
				.compact();
		logger.info("JwtUtil.createToken.END");

		return compact;
	}

	public String doGenerateRefreshToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + refreshExpirationDateInMs))
				.signWith(SignatureAlgorithm.HS512, secret).compact();

	}

	/**
	 * This method is used to validate token based on the given token and
	 * userDetails as parameter. First from the token we will extract the username
	 * and then will check in the database whether the token extracted username and
	 * the user residing in database is same or not and also will check whether the
	 * token has been expired or not
	 * 
	 * @param token
	 * @param userDetails
	 * @return
	 */
	public Boolean validateToken(String token) {
		logger.info("JwtUtil.validateToken.START");

		try {
			Jwts.parser().setSigningKey(secretkey).parseClaimsJws(token).getBody();
			logger.info("JwtUtil.validateToken.END");

			return true;
		} catch (Exception e) {
			logger.info("JwtUtil.validateToken.EXCEPTION");
			return false;
		}

	}
}