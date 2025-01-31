package com.fleetility.sec;

import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtTokenUtil extends JwTokenUtil {

	@Override
	public String generateToken(UserInfo userInfo) {
    	return generateToken(userInfo, expirationMs);
    }
    
    @Override
	public String generateRefreshToken(UserInfo userInfo) {
    	return generateToken(userInfo, refreshExpirationMs);
	}
    

	private String generateToken(UserInfo userInfo, long expirationMs) {
        return Jwts.builder()
          .subject((userInfo.getUsername()))
          .issuedAt(new Date())
          .expiration(new Date((new Date()).getTime() + expirationMs))
          .claims(prepareClaims(userInfo))
          .signWith(getSecretSigningKey())
          .compact();
    }
    
    @Override
    public JwtParser getParser() {
    	return Jwts.parser().verifyWith(getSecretSigningKey()).build();
    }


    
	


}