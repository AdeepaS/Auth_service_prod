package com.auth.service.config.jwtConfig;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.UUID;

public class CustomAuthenticationDetails extends WebAuthenticationDetails {
    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationDetails.class);
    private final String correlationId;

    private final String sessionId;

    private UUID useId;

    public CustomAuthenticationDetails(HttpServletRequest request, String correlationId , String sessionId , UUID userId) {
        super(request);
        this.correlationId = correlationId;
        this.sessionId = sessionId;
        this.useId = userId;
        logger.info("SessionId: {}, correlation ID: {} , userId: {} [CustomAuthenticationDetails:CustomAuthenticationDetails] CustomAuthenticationDetails created", sessionId ,correlationId , userId);
    }

    @Override
    public String toString() {
        return super.toString() + "; correlationId: " + correlationId;
    }

    public String getCorrelationId() {
        logger.info("SessionId: {}, correlation ID: {} , userId: {} [CustomAuthenticationDetails:getCorrelationId] Inside CustomAuthenticationDetails", sessionId ,correlationId , useId);
        return correlationId;
    }

    public String getSessionId() {
        logger.info("SessionId: {}, correlation ID: {} , userId: {} [CustomAuthenticationDetails:getCorrelationId] Inside CustomAuthenticationDetails", sessionId ,correlationId , useId);
        return sessionId;
    }

    public UUID getId() {
        logger.info("SessionId: {}, correlation ID: {} , userId: {} [CustomAuthenticationDetails:getCorrelationId] Inside CustomAuthenticationDetails", sessionId ,correlationId , useId);
        return useId;
    }
}