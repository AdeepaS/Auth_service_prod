package com.auth.service.service;

public interface EmailService {
    boolean sendEmail(String email, String subject, String text);
    boolean sendOtpEmail(String email, String otp);

}
