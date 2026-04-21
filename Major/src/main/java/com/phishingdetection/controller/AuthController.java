package com.phishingdetection.controller;

import com.phishingdetection.model.OTP;
import com.phishingdetection.model.User;
import com.phishingdetection.repository.OTPRepository;
import com.phishingdetection.repository.UserRepository;
import com.phishingdetection.service.EmailService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserRepository userRepository;
    private final OTPRepository otpRepository;
    private final EmailService emailService;
    
    public AuthController(UserRepository userRepository, OTPRepository otpRepository, EmailService emailService) {
        this.userRepository = userRepository;
        this.otpRepository = otpRepository;
        this.emailService = emailService;
    }
    
    // 1. Send OTP to email
    @PostMapping("/send-otp")
    public ResponseEntity<Map<String, Object>> sendOtp(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        Map<String, Object> response = new HashMap<>();
        
        if (email == null || email.isEmpty()) {
            response.put("success", false);
            response.put("message", "Email is required");
            return ResponseEntity.badRequest().body(response);
        }
        
        // Generate 6-digit OTP
        String otp = String.format("%06d", new Random().nextInt(999999));
        
        // Delete old OTPs for this email
        otpRepository.deleteByEmail(email);
        
        // Save new OTP
        OTP otpEntity = new OTP();
        otpEntity.setEmail(email);
        otpEntity.setOtp(otp);
        otpEntity.setExpiryTime(LocalDateTime.now().plusMinutes(5));
        otpRepository.save(otpEntity);
        
        // Send email
        try {
            emailService.sendOtpEmail(email, otp);
            response.put("success", true);
            response.put("message", "OTP sent to your email");
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "Failed to send OTP: " + e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }
    
    // 2. Verify OTP
    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, Object>> verifyOtp(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String otp = request.get("otp");
        Map<String, Object> response = new HashMap<>();
        
        Optional<OTP> otpOpt = otpRepository.findByEmailAndOtpAndVerifiedFalse(email, otp);
        
        if (otpOpt.isPresent()) {
            OTP otpEntity = otpOpt.get();
            if (otpEntity.getExpiryTime().isAfter(LocalDateTime.now())) {
                otpEntity.setVerified(true);
                otpRepository.save(otpEntity);
                response.put("success", true);
                response.put("message", "OTP verified successfully");
            } else {
                response.put("success", false);
                response.put("message", "OTP has expired");
            }
        } else {
            response.put("success", false);
            response.put("message", "Invalid OTP");
        }
        
        return ResponseEntity.ok(response);
    }
    
    // 3. Sign Up (after OTP verification)
    @PostMapping("/signup")
    public ResponseEntity<Map<String, Object>> signup(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String username = request.get("username");
        String password = request.get("password");
        
        Map<String, Object> response = new HashMap<>();
        
        // Check if OTP is verified
        Optional<OTP> otpOpt = otpRepository.findByEmailAndVerifiedTrue(email);
        if (otpOpt.isEmpty()) {
            response.put("success", false);
            response.put("message", "Please verify your email with OTP first");
            return ResponseEntity.badRequest().body(response);
        }
        
        // Check if email already exists
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
        
        // Create user
        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(password);
        user.setVerified(true);
        user.setCreatedAt(LocalDateTime.now());
        
        userRepository.save(user);
        
        response.put("success", true);
        response.put("message", "Account created successfully");
        return ResponseEntity.ok(response);
    }
    
    // 4. Login
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        String emailOrUsername = request.get("email");
        String password = request.get("password");
        
        Map<String, Object> response = new HashMap<>();
        
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