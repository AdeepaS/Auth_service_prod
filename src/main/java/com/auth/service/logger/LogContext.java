package com.auth.service.logger;

import java.util.UUID;

import com.auth.service.util.UserUtil;
import org.springframework.stereotype.Component;

/**
 * Provides access to logging context information.
 * This implementation delegates to UserUtil to retrieve authentication details.
 */
@Component
public class LogContext {
    private static UserUtil userUtil;

    // For backward compatibility - these don't actually store values anymore
    private static final ThreadLocal<String> sessionIdFallback = new ThreadLocal<>();
    private static final ThreadLocal<String> correlationIdFallback = new ThreadLocal<>();
    private static final ThreadLocal<UUID> userIdFallback = new ThreadLocal<>();

    // Spring will inject the UserUtil bean
    public LogContext(UserUtil userUtilInstance) {
        LogContext.userUtil = userUtilInstance;
    }

    public static void setSessionId(String id) {
        // Store in fallback for cases where authentication isn't available
        sessionIdFallback.set(id);
    }

    public static void setCorrelationId(String id) {
        // Store in fallback for cases where authentication isn't available
        correlationIdFallback.set(id);
    }

    public static void setId(UUID id) {
        // Store in fallback for cases where authentication isn't available
        userIdFallback.set(id);
    }

    public static String getSessionId() {
        try {
            // First try to get from authentication
            String sessionId = userUtil != null ? userUtil.getSessionIdFromAuthentication() : null;
            // If not available, use fallback
            return sessionId != null ? sessionId : sessionIdFallback.get();
        } catch (Exception e) {
            return sessionIdFallback.get();
        }
    }

    public static String getCorrelationId() {
        try {
            // First try to get from authentication
            String correlationId = userUtil != null ? userUtil.getCorrelationIdFromAuthentication() : null;
            // If not available, use fallback
            return correlationId != null ? correlationId : correlationIdFallback.get();
        } catch (Exception e) {
            return correlationIdFallback.get();
        }
    }

    public static UUID getId() {
        try {
            // First try to get from authentication
            UUID userId = userUtil != null ? userUtil.getUserIdFromAuthentication() : null;
            // If not available, use fallback
            return userId != null ? userId : userIdFallback.get();
        } catch (Exception e) {
            return userIdFallback.get();
        }
    }

    public static void clear() {
        sessionIdFallback.remove();
        correlationIdFallback.remove();
        userIdFallback.remove();
    }
}
