package com.feedback.anonymousfeedback.controller;

import com.feedback.anonymousfeedback.dto.RegisterRequest;
import com.feedback.anonymousfeedback.security.JwtUtil;
import com.feedback.anonymousfeedback.model.User;
import com.feedback.anonymousfeedback.repository.UserRepository;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:63342")
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    // =========================
    // USER REGISTRATION
    // =========================

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestBody RegisterRequest request) {

        // Check duplicate username
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body("Username already exists");
        }

        User user = new User();

        user.setUsername(request.getUsername());

        // Never store plain-text password
        user.setPassword(
                passwordEncoder.encode(request.getPassword())
        );

        // Public registration can ONLY create USER accounts
        user.setRole("USER");

        userRepository.save(user);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body("User registered successfully");
    }


    // =========================
    // LOGIN
    // =========================

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody AuthRequest request) {

        Authentication auth =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.username,
                                request.password
                        )
                );

        String role = auth.getAuthorities()
                .iterator()
                .next()
                .getAuthority()
                .replace("ROLE_", "");

        String token =
                jwtUtil.generateToken(
                        request.username,
                        role
                );

        return ResponseEntity.ok(
                new AuthResponse(
                        token,
                        request.username,
                        role
                )
        );
    }


    // =========================
    // LOGIN REQUEST
    // =========================

    static class AuthRequest {

        public String username;
        public String password;
    }


    // =========================
    // LOGIN RESPONSE
    // =========================

    static class AuthResponse {

        public String token;
        public String username;
        public String role;

        public AuthResponse(
                String token,
                String username,
                String role) {

            this.token = token;
            this.username = username;
            this.role = role;
        }
    }
}