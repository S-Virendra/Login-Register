package com.virendra.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

   

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        // 1️⃣ Authorization header uthao
        String authHeader = request.getHeader("Authorization");

        // 2️⃣ Check Bearer token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {

            // 3️⃣ Token extract
            String token = authHeader.substring(7);

            // 4️⃣ Token validate (UPDATED JwtUtil)
            if (jwtUtil.isTokenValid(token)) {

                // 5️⃣ User identity nikalo
                String email = jwtUtil.extractEmail(token);

                // 6️⃣ Authentication object banao
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                email, null, null);

                authentication.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request));

                // 7️⃣ SecurityContext me set karo
                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);
            }
        }

        // 8️⃣ Request ko next filter / controller tak bhejo
        filterChain.doFilter(request, response);
    }
}

