package com.auth.service.logger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4jAdapter implements LoggerAdapter{

    private final Logger logger = LogManager.getLogger(Log4jAdapter.class);

    @Override
    public void info(String message, Object... args) {
        logger.info(message, args);
    }

    @Override
    public void warn(String message, Object... args) {
        logger.warn(message, args);
    }

    @Override
    public void error(String message, Object... args) {
        logger.error(message, args);
    }

    @Override
    public void debug(String message, Object... args) {
        logger.debug(message, args);
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

        logger.info(contextualMessage, args);
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

        logger.warn(contextualMessage, args);
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

        logger.error(contextualMessage, args);
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

        logger.debug(contextualMessage, args);
    }
}