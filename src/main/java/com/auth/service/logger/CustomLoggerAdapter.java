package com.auth.service.logger;

public class CustomLoggerAdapter implements LoggerAdapter{
    @Override
    public void info(String message, Object... args) {
        System.out.printf("INFO: " + message + "%n", args);
    }

    @Override
    public void warn(String message, Object... args) {
        System.out.printf("WARN: " + message + "%n", args);
    }

    @Override
    public void error(String message, Object... args) {
        System.err.printf("ERROR: " + message + "%n", args);
    }

    @Override
    public void debug(String message, Object... args) {
        System.out.printf("DEBUG: " + message + "%n", args);
    }

    @Override
    public void infoWithContext(String className, String methodName, String message, Object... args) {
        String sessionId = LogContext.getSessionId();
        String correlationId = LogContext.getCorrelationId();
        java.util.UUID userId = LogContext.getId();

        String contextualMessage = String.format(
                "SessionId: %s, CorrelationId: %s, UserId: %s, [%s:%s] %s",
                sessionId, correlationId, userId, className, methodName, message
        );

        System.out.printf("INFO: " + contextualMessage + "%n", args);
    }

    @Override
    public void warnWithContext(String className, String methodName, String message, Object... args) {
        String sessionId = LogContext.getSessionId();
        String correlationId = LogContext.getCorrelationId();
        java.util.UUID userId = LogContext.getId();

        String contextualMessage = String.format(
                "SessionId: %s, CorrelationId: %s, UserId: %s, [%s:%s] %s",
                sessionId, correlationId, userId, className, methodName, message
        );

        System.out.printf("WARN: " + contextualMessage + "%n", args);
    }

    @Override
    public void errorWithContext(String className, String methodName, String message, Object... args) {
        String sessionId = LogContext.getSessionId();
        String correlationId = LogContext.getCorrelationId();
        java.util.UUID userId = LogContext.getId();

        String contextualMessage = String.format(
                "SessionId: %s, CorrelationId: %s, UserId: %s, [%s:%s] %s",
                sessionId, correlationId, userId, className, methodName, message
        );

        System.err.printf("ERROR: " + contextualMessage + "%n", args);
    }

    @Override
    public void debugWithContext(String className, String methodName, String message, Object... args) {
        String sessionId = LogContext.getSessionId();
        String correlationId = LogContext.getCorrelationId();
        java.util.UUID userId = LogContext.getId();

        String contextualMessage = String.format(
                "SessionId: %s, CorrelationId: %s, UserId: %s, [%s:%s] %s",
                sessionId, correlationId, userId, className, methodName, message
        );

        System.out.printf("DEBUG: " + contextualMessage + "%n", args);
    }
}
