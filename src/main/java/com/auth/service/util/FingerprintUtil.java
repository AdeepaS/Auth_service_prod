package com.auth.service.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for generating fingerprints based on client information
 */
@Component
public class FingerprintUtil {
    private static final Logger logger = LoggerFactory.getLogger(FingerprintUtil.class);

    /**
     * Generates a fingerprint hash based on request data
     * @param request The HTTP request containing client information
     * @return A base64 encoded SHA-256 hash of client information
     */
    public String generateFingerprint(HttpServletRequest request, String username) {
        // Collect data points that identify the client
        String userAgent = request.getHeader("User-Agent") != null ? request.getHeader("User-Agent") : "";
        String ipAddress = request.getRemoteAddr();
        String acceptLanguage = request.getHeader("Accept-Language") != null ? request.getHeader("Accept-Language") : "";

        // Combine the values
        String fingerprintSource = userAgent + "|" + ipAddress + "|" + acceptLanguage + username;

        logger.debug("Generating fingerprint from source data");

        // Hash the combined string using SHA-256
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fingerprintSource.getBytes(StandardCharsets.UTF_8));
            String fingerprint = Base64.getEncoder().encodeToString(hash);

            logger.debug("Fingerprint generated successfully");
            return fingerprint;
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to generate fingerprint hash", e);
            throw new RuntimeException("Failed to generate fingerprint hash", e);
        }
    }
}
