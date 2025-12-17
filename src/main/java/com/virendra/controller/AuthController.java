package com.virendra.controller;

import org.springframework.web.bind.annotation.*;

import com.virendra.dto.LoginRequest;
import com.virendra.dto.RegisterRequest;
import com.virendra.service.AuthService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // 📝 Register API
    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    // 🔐 Login API (returns JWT)
    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }
}


