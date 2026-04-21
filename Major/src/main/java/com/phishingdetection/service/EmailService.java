package com.phishingdetection.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    
    private final JavaMailSender mailSender;
    
    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }
    
    public void sendOtpEmail(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("PhishShield - Your OTP Code");
        message.setText("Your OTP for PhishShield verification is: " + otp + "\n\nThis OTP is valid for 5 minutes.\n\nThank you for using PhishShield!");
        mailSender.send(message);
        System.out.println("OTP email sent to: " + to);
    }
}