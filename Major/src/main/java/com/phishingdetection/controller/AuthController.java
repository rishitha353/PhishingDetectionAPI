package com.phishingdetection.controller;

import com.phishingdetection.model.User;
import com.phishingdetection.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserRepository userRepository;

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostMapping("/signup")
    public ResponseEntity<Map<String, Object>> signup(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String username = request.get("username");
        String password = request.get("password");
        
        Map<String, Object> response = new HashMap<>();
        
        // Validate input
        if (email == null || username == null || password == null) {
            response.put("success", false);
            response.put("message", "All fields are required");
            return ResponseEntity.badRequest().body(response);
        }
        
        // Check if email exists
        if (userRepository.existsByEmail(email)) {
            response.put("success", false);
            response.put("message", "Email already registered");
            return ResponseEntity.badRequest().body(response);
        }
        
        // Check if username exists
        if (userRepository.existsByUsername(username)) {
            response.put("success", false);
            response.put("message", "Username already taken");
            return ResponseEntity.badRequest().body(response);
        }
        
        // Create new user
        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(password); // TODO: Add password hashing in production
        user.setCreatedAt(LocalDateTime.now());
        
        userRepository.save(user);
        
        response.put("success", true);
        response.put("message", "User registered successfully");
        response.put("username", username);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        String emailOrUsername = request.get("email");
        String password = request.get("password");
        
        Map<String, Object> response = new HashMap<>();
        
        if (emailOrUsername == null || password == null) {
            response.put("success", false);
            response.put("message", "Email/Username and password required");
            return ResponseEntity.badRequest().body(response);
        }
        
        // Try to find by email first, then by username
        Optional<User> userOpt = userRepository.findByEmail(emailOrUsername);
        if (!userOpt.isPresent()) {
            userOpt = userRepository.findByUsername(emailOrUsername);
        }
        
        if (!userOpt.isPresent()) {
            response.put("success", false);
            response.put("message", "Invalid credentials");
            return ResponseEntity.badRequest().body(response);
        }
        
        User user = userOpt.get();
        
        // Check password
        if (!user.getPassword().equals(password)) {
            response.put("success", false);
            response.put("message", "Invalid credentials");
            return ResponseEntity.badRequest().body(response);
        }
        
        response.put("success", true);
        response.put("message", "Login successful");
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        return ResponseEntity.ok(response);
    }
}