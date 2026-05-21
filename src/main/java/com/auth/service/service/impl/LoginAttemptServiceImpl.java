package com.auth.service.service.impl;

import com.auth.service.entity.LoginAttempt;
import com.auth.service.repository.LoginAttemptRepository;
import com.auth.service.service.LoginAttemptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class LoginAttemptServiceImpl implements LoginAttemptService {
    private static final int MAX_ATTEMPT = 3;
    private static final long BLOCK_DURATION_MINUTES = 15;
    private static final Logger logger = LoggerFactory.getLogger(LoginAttemptServiceImpl.class);

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    @Transactional
    public void loginSucceeded(String username) {
        LoginAttempt loginAttempt = loginAttemptRepository.findByUsername(username);
        if (loginAttempt != null) {
            loginAttempt.setAttemptCount(0);
            loginAttempt.setBlocked(false);
            loginAttempt.setBlockExpireTime(null);
            loginAttemptRepository.save(loginAttempt);
        }
    }

    @Transactional
    public void loginFailed(String username) {
        LoginAttempt loginAttempt = loginAttemptRepository.findByUsername(username);
        LocalDateTime now = LocalDateTime.now();

        if (loginAttempt == null) {
            // If no previous login attempts, initialize a new LoginAttempt record
            loginAttempt = new LoginAttempt();
            loginAttempt.setUsername(username);
            loginAttempt.setAttemptCount(1);
            loginAttempt.setLastAttemptTime(now);
            loginAttemptRepository.save(loginAttempt);
            return;
        }

        // Check if the last attempt was more than 15 minutes ago
        if (loginAttempt.getLastAttemptTime() != null &&
                now.isAfter(loginAttempt.getLastAttemptTime().plusMinutes(15))) {
            // If the last attempt was more than 15 minutes ago, reset the attempt count to 1
            loginAttempt.setAttemptCount(1);
        } else {
            // Otherwise, increment the failed attempt count
            loginAttempt.setAttemptCount(loginAttempt.getAttemptCount() + 1);
        }

        loginAttempt.setLastAttemptTime(now);  // Update the last attempt time

        // If the failed attempt count reaches MAX_ATTEMPT (e.g., 3), check if it's within the last 15 minutes
        if (loginAttempt.getAttemptCount() >= MAX_ATTEMPT) {
            loginAttempt.setBlocked(true);
            loginAttempt.setBlockExpireTime(now.plusMinutes(BLOCK_DURATION_MINUTES));
        }

        // Save the updated login attempt record
        loginAttemptRepository.save(loginAttempt);
    }

    public boolean isBlocked(String username) {
        if (username == null || username.trim().isEmpty()) {
            logger.warn("Attempted to check block status with null or empty username");
            return false;
        }

        logger.info("Checking if user {} is blocked", username);
        LoginAttempt loginAttempt = loginAttemptRepository.findByUsername(username);
        if (loginAttempt != null) {
            logger.info("Found login attempt record for user {}: {}", username, loginAttempt);
            if (loginAttempt.isBlocked()) {
                if (LocalDateTime.now().isAfter(loginAttempt.getBlockExpireTime())) {
                    loginAttempt.setBlocked(false);
                    loginAttempt.setAttemptCount(0);
                    loginAttempt.setBlockExpireTime(null);
                    loginAttemptRepository.save(loginAttempt);
                    return false;
                }
                return true;
            }
        } else {
            logger.info("No login attempt record found for user {}", username);
        }
        return false;
    }
}

