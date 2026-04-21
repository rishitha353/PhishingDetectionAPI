package com.phishingdetection.repository;

import com.phishingdetection.model.OTP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface OTPRepository extends JpaRepository<OTP, Long> {
    Optional<OTP> findByEmailAndOtpAndVerifiedFalse(String email, String otp);
    void deleteByEmail(String email);
    Optional<OTP> findByEmailAndVerifiedTrue(String email);
}