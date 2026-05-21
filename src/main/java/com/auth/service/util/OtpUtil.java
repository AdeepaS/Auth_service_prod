package com.auth.service.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Random;

@Component
public class OtpUtil {

    private static final Logger log = LoggerFactory.getLogger(OtpUtil.class);

    public String generateOtp() {
        return String.format("%06d", new Random().nextInt(999999));
    }

    public void sendOtpSms(String phoneNumber, String otp) {
        System.out.println("Sending OTP " + otp + " to " + phoneNumber);
    }

    public static LocalDateTime generateOtpExpiry() {
        return LocalDateTime.now().plusMinutes(5); // OTP valid for 5 minutes
    }

    public void sendOtpEmail(String email, String code) {
        System.out.println("Sending verification code " + code + " to " + email);
    }
}
