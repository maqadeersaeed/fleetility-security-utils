package com.fleetility.sec;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.fleetility.exception.FleetilityException;
import com.fleetility.exception.InvalidUserException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public abstract class JwTokenUtil {

	@Value("${app.fleetility.security.secret-key}")
	protected  String SECRET;

	@Value("${app.fleetility.security.jwt-expiration-ms}")
	protected long expirationMs;
	
	@Value("${app.fleetility.security.jwt-refresh-expiration-ms}")
	protected long refreshExpirationMs;
	
	protected static final String CLAIM_USERNAME = "CLAIM_USERNAME";
	protected static final String CLAIM_USER_ID = "CLAIM_USER_ID";
	protected static final String CLAIM_COMPANY_ID = "CLAIM_COMPANY_ID";
	protected static final String CLAIM_AUTHORITIES = "CLAIM_AUTHORITIES";
	
	private JwtParser parser = null;

	@PostConstruct
	public void init() {
		this.parser = getParser();
	}

	public abstract String generateToken(UserInfo userInfo);
	
	public abstract String generateRefreshToken(UserInfo userInfo);

	public abstract JwtParser getParser();

	public boolean validateToken(String authToken) throws InvalidUserException, ExpiredJwtException, FleetilityException {
		boolean valid = false;
		try {
			valid = !isInvalidToken(authToken);
		} catch (SignatureException e) {
			log.error(e.getMessage() + "  SignatureException ");
			throw new InvalidUserException("Invalid token  SignatureException", null, null);
		} catch (ExpiredJwtException e) {
			log.error(e.getMessage() + "  ExpiredJwtException ");
			throw new ExpiredJwtException(null, null, "JWT token is expired: {}");
		} catch (Exception e) {
			log.error(e.getMessage() + "  Exception ");
			throw new FleetilityException("Invalid token Exception", null, null);
		}
		return valid;
	}

	public boolean isValidToken(String authToken) {
		boolean valid = false;
		try {
			valid = !isInvalidToken(authToken);
		} catch (Exception e) {
			valid = false;
		}
		return valid;
	}
	
	public UserInfo extractUserInfoFromToken(final String token) {
	    Claims claims = extractClaims(token);
	    UserInfo userInfo = new UserInfo();

	    // Extract and map claims to fleetilityUserDetails fields
	    userInfo.setUsername((String) claims.get(CLAIM_USERNAME));
	    userInfo.setUserId((String) claims.get(CLAIM_USER_ID)); // Assuming userId is a String, adapt if it's a different type
	    userInfo.setCompanyId((String) claims.get(CLAIM_COMPANY_ID)); // Adapt if companyId has a different type
	    userInfo.setAuthorities(claims.get(CLAIM_AUTHORITIES, List.class));

	    return userInfo;
	}


	public Claims extractClaims(final String token) {
		Claims claims = parser.parseEncryptedClaims(token).getPayload();
		return claims;
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractClaims(token);
		return claimsResolver.apply(claims);
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	protected Map<String, Object> prepareClaims(UserInfo userInfo) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(CLAIM_USERNAME, userInfo.getUsername());
        claims.put(CLAIM_USER_ID, userInfo.getUserId());
        claims.put(CLAIM_COMPANY_ID, userInfo.getCompanyId());
//        claims.put(CLAIM_AUTHORITIES, userDetails.getAuthorities().stream().map(a -> a.getAuthority()).toList());
        claims.put(CLAIM_AUTHORITIES, userInfo.getAuthorities());
        return claims;
	}

	private boolean isInvalidToken(String token) {
		final String username = extractUsername(token);
		if (username != null && !username.isBlank() && !username.isEmpty()) {
			return false;
		}
		return true;
	}

	protected SecretKey getSecretSigningKey() {
//      return Jwts.SIG.HS256.key().build();
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
//	public void getAuthenticationToken(final String token, final Authentication existingAuth, final fleetilityUserDetails userDetails) {
//        final Claims claims = extractClaims(token);
//
//        final Collection<? extends GrantedAuthority> authorities =
//                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
//                        .map(SimpleGrantedAuthority::new)
//                        .collect(Collectors.toList());
//
//        return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
//    }

}