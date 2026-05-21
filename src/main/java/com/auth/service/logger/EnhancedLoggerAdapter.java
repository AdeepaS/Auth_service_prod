package com.auth.service.logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/**
 * Enhanced logger that automatically includes context information.
 */
@Component
public class EnhancedLoggerAdapter {
    private final LoggerAdapter delegate;

    @Autowired
    public EnhancedLoggerAdapter(@Qualifier("enhancedLoggerAdapterDelegate") LoggerAdapter delegate) {
        this.delegate = delegate;
    }

    public void info(String message, Object... args) {
        String callerInfo = getCallerInfo();
        String[] parts = callerInfo.split(":");
        delegate.infoWithContext(parts[0], parts[1], message, args);
    }

    public void warn(String message, Object... args) {
        String callerInfo = getCallerInfo();
        String[] parts = callerInfo.split(":");
        delegate.warnWithContext(parts[0], parts[1], message, args);
    }

    public void error(String message, Object... args) {
        String callerInfo = getCallerInfo();
        String[] parts = callerInfo.split(":");
        delegate.errorWithContext(parts[0], parts[1], message, args);
    }

    public void debug(String message, Object... args) {
        String callerInfo = getCallerInfo();
        String[] parts = callerInfo.split(":");
        delegate.debugWithContext(parts[0], parts[1], message, args);
    }

    private String getCallerInfo() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        // Index 0 is getStackTrace, 1 is getCallerInfo, 2 is the log method, 3 is the caller
        if (stackTrace.length >= 4) {
            StackTraceElement caller = stackTrace[3];
            String className = caller.getClassName();
            String methodName = caller.getMethodName();
            // Get just the simple class name
            if (className.contains(".")) {
                className = className.substring(className.lastIndexOf('.') + 1);
            }
            return className + ":" + methodName;
        }
        return "Unknown:unknown";
    }
}

