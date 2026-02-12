package com.sahil.springsecuritydemo.configs.security;


import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import com.sahil.springsecuritydemo.enums.Role;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;



import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public String generateToken(String email, Set<Role> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("roles", roles.stream().map(Role::name).collect(Collectors.toList()));
        return createToken(claims);
    }

    public String extractEmail(String token) {
        return extractClaims(token).get("email").toString();
    }

    public Date extractExpiration(String token) {
        return extractClaims(token).getExpiration();
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    public Boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String email = extractEmail(token);
            boolean isTokenExpired = isTokenExpired(token);

            boolean usernameMatches = email.equals(userDetails.getUsername());
            return usernameMatches && !isTokenExpired;
        } catch (Exception e) {
            return false;
        }
    }

    public Claims extractClaims(String token) throws JwtException {
        try {
            return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
        } catch (SignatureException e) {
            throw new JwtException("Invalid JWT signature");
        }
        catch (MalformedJwtException e) {
            throw new JwtException("Invalid JWT token");
        }
        catch (ExpiredJwtException e) {
            throw new JwtException("JWT token has expired");
        }
        catch (UnsupportedJwtException e) {
            throw new JwtException("Unsupported JWT token");
        }
        catch (Exception e) {
            throw new JwtException("Invalid JWT token");
        }
    }

    private SecretKey getSigningKey() {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(bytes);
    }


    private String createToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .subject(claims.get("email").toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }
}
