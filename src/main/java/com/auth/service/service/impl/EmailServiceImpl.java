package com.auth.service.service.impl;

import com.auth.service.exception.EmailException;
import com.auth.service.repository.UserRepo;
import com.auth.service.service.EmailService;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import java.util.regex.Pattern;
import org.apache.commons.validator.routines.EmailValidator;

@Service
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender javaMailSender;
    private final UserRepo userRepo;

    private static final Logger logger = LoggerFactory.getLogger(EmailServiceImpl.class);

    @Autowired
    public EmailServiceImpl(JavaMailSender javaMailSender, UserRepo userRepo) {
        this.javaMailSender = javaMailSender;
        this.userRepo = userRepo;
    }

    @Override
    public boolean sendEmail(String email, String subject, String text) {
        if (!isValidEmail(email)) {
            logger.error("Email failed Apache Commons Validator check");
            logger.debug("Invalid email: {}", maskEmail(email));
            throw EmailException.invalidAddress("Invalid email address: " + email);
        }
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setTo(email);
            helper.setFrom("lms@pucsl.gov.lk");
            helper.setSubject(subject);
            helper.setText(text, true);

            javaMailSender.send(mimeMessage);
        } catch (Exception e) {
            throw EmailException.sendingFailed(e.getMessage());
        }
        return false;
    }

    @Override
    public boolean sendOtpEmail(String email, String otp) {
        if (!isValidEmail(email)) {
            logger.error("Invalid email address provided");
            logger.debug("Invalid email: {}", maskEmail(email));
            return false;
        }
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            String subject = "Your OTP Code";
            String text = "<p>Hello,</p>"
                    + "<p>Your OTP code is: <b>" + otp + "</b></p>"
                    + "<p>This OTP is valid for a short period. Please do not share it with anyone.</p>"
                    + "<p>Regards,<br>Support Team</p>";

            helper.setTo(email);
            helper.setFrom("lms@pucsl.gov.lk");
            helper.setSubject(subject);
            helper.setText(text, true); // `true` enables HTML content

            javaMailSender.send(mimeMessage);
            logger.info("OTP email sent successfully");
            logger.debug("OTP sent to: {}", maskEmail(email));
            return true;
        } catch (Exception e) {
            throw EmailException.sendingFailed(e.getMessage());
        }
    }

    private boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            logger.error("Email address is null or empty");
            return false;
        }

        EmailValidator validator = EmailValidator.getInstance();
        boolean isValid = validator.isValid(email);
        if (!isValid) {
            logger.error("Email validation failed");
            logger.debug("Invalid email: {}", maskEmail(email));
            // You can add more detailed checks here to see why it failed
            logger.debug("Email contains @: {}", email.contains("@"));
            logger.debug("Email has local part");
            logger.debug("Email has domain");
        } else {
            logger.debug("Email validation passed");
        }


        // Check for disposable email domains (you can expand this list)
        String[] disposableDomains = {"mailinator.com", "guerrillamail.com", "temp-mail.org"};
        String domain = email.substring(email.lastIndexOf("@") + 1).toLowerCase();
        for (String disposableDomain : disposableDomains) {
            if (domain.equals(disposableDomain)) {
                logger.error("Disposable email domain detected");
                logger.debug("Disposable domain email: {}", maskEmail(email));
                return false;
            }
        }

        logger.debug("Email validation passed");
        return true;
    }

    // Helper method to mask emails for safe logging
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        String[] parts = email.split("@");
        return parts[0].charAt(0) + "***@" + parts[1];
    }
}

