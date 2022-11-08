package com.talhacgdem.security.security;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${twitter.clone.secretkey}")
    private String APP_SECRET;

    @Value("${twitter.clone.expiresin}")
    private Long EXPIRES_IN;

    public String generateJwtToken(Authentication authentication){
        JwtUserDetails userDetails = (JwtUserDetails) authentication.getPrincipal();
        Date expireDate = new Date(new Date().getTime() + EXPIRES_IN);
        return Jwts.builder().setSubject(Long.toString(userDetails.getId()))
                .setIssuedAt(new Date()).setExpiration(expireDate)
                .signWith(SignatureAlgorithm.HS512, APP_SECRET).compact();
    }

    Jws<Claims> parseToken(String token){
        return Jwts.parser().setSigningKey(APP_SECRET).parseClaimsJws(token);
    }

    Long getUserIdFromJwtToken(String token){
        Claims claims = parseToken(token).getBody();
        return Long.parseLong(claims.getSubject());
    }

    boolean validateToken(String token){
        try {
            return !isTokenExpired(parseToken(token).getBody());
        }catch (
                SignatureException |
                IllegalArgumentException |
                UnsupportedJwtException |
                ExpiredJwtException |
                MalformedJwtException signatureException
        ){
            return false;
        }
    }

    private boolean isTokenExpired(Claims claims) {
        Date expiration = claims.getExpiration();
        return expiration.before(new Date());
    }
}
