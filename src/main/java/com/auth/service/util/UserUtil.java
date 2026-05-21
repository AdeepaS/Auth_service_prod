package com.auth.service.util;
import com.auth.service.config.jwtConfig.CustomAuthenticationDetails;
import com.auth.service.config.jwtConfig.JwtTokenUtils;
import com.auth.service.logger.EnhancedLoggerAdapter;
import com.auth.service.logger.LoggerAdapter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

@RequiredArgsConstructor
@Component
public class UserUtil {
    private final EnhancedLoggerAdapter logger;
    private final JwtTokenUtils jwtTokenUtils;
    @Autowired
    private HttpServletRequest request;

    public UUID getUserIdFromAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            CustomAuthenticationDetails customDetails = (CustomAuthenticationDetails) request.getAttribute("CUSTOM_AUTH_DETAILS");
            return customDetails.getId();
        }
        logger.warn("[UserUtil:getUserIdFromAuthentication] CustomAuthenticationDetails not found in request details.");
        return null;
    }

    public static String hashWithMD5(String token) {
        try {
            // Create an MD5 MessageDigest instance
            MessageDigest md = MessageDigest.getInstance("MD5");

            // Compute the hash
            byte[] hashBytes = md.digest(token.getBytes());

            // Convert the hash bytes to a hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not available", e);
        }
    }

//    public String getSessionIdFromAuthentication() {
//        String correlationId = getCorrelationIdFromAuthentication();
//        Authentication authentication2 = SecurityContextHolder.getContext().getAuthentication();
//        if (authentication2 != null && authentication2.getPrincipal() instanceof Jwt) {
//            Jwt jwt = (Jwt) authentication2.getPrincipal();
//            logger.info("[UserUtil:getUserIdFromAuthentication] Extracting user ID from JWT token for correlation ID: {}", correlationId);
//            return hashWithMD5(jwt.getTokenValue());
//        }
//        return null;
//    }

    public String getSessionIdFromAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            CustomAuthenticationDetails customDetails = (CustomAuthenticationDetails) request.getAttribute("CUSTOM_AUTH_DETAILS");
            return customDetails.getSessionId();
        }
        logger.warn("[UserUtil:getUserIdFromAuthentication] CustomAuthenticationDetails not found in request details.");
        return null;
    }

    public String getCorrelationIdFromAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            CustomAuthenticationDetails customDetails = (CustomAuthenticationDetails) request.getAttribute("CUSTOM_AUTH_DETAILS");
            return customDetails.getCorrelationId();
        }
        logger.warn("[UserUtil:getUserIdFromAuthentication] CustomAuthenticationDetails not found in request details.");
        return null;
    }

    public UUID getId() {
        UUID userId = getUserIdFromAuthentication();
        String correlationId = getCorrelationIdFromAuthentication();
        if (userId == null) {
            logger.error("[UserUtil:getUserIdFromAuthentication] User ID is missing from the authentication token for correlation ID:", correlationId);
            throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "User ID is missing from the authentication token");
        }
        return userId;
    }


    public String generateCorrelationId() {
        return java.util.UUID.randomUUID().toString();
    }
}

