package com.virendra.security;

import java.security.Key;
import java.util.Date;
import java.nio.charset.StandardCharsets;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    private static final String SECRET_KEY =
            "virendra_jwt_secret_key_12345_very_secure";

    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(
                SECRET_KEY.getBytes(StandardCharsets.UTF_8)
        );
    }

    // 🔹 Generate Token
    public String generateToken(String email) {

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(
                        new Date(System.currentTimeMillis() + EXPIRATION_TIME)
                )
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // 🔹 Extract Email
    public String extractEmail(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // 🔹 Validate Token
    public boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);

            return true;
        } catch (JwtException e) {
            return false;
        }
    }
}

