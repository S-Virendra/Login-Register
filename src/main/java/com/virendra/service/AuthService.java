package com.virendra.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.virendra.dto.LoginRequest;
import com.virendra.dto.RegisterRequest;
import com.virendra.model.User;
import com.virendra.repository.UserRepository;
import com.virendra.security.JwtUtil;

import lombok.RequiredArgsConstructor;




@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    
    // 🔐 REGISTER
    public String register(RegisterRequest req) {

        if (userRepository.existsByEmail(req.getEmail())) {
            return "Email already exists";
        }

        User user = new User();
        user.setEmail(req.getEmail());
        user.setUsername(req.getUsername());

        // BCrypt password
        user.setPassword(passwordEncoder.encode(req.getPassword()));

        userRepository.save(user);

        return "User registered successfully";
    }

    // 🔑 LOGIN
    public String login(LoginRequest req) {

        User user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        // 🔥 JWT TOKEN
        return jwtUtil.generateToken(user.getEmail());
    }
}




