package com.auth.service.logger;

import org.springframework.stereotype.Component;

@Component
public interface LoggerAdapter {
    void info(String message, Object... args);
    void warn(String message, Object... args);
    void error(String message, Object... args);
    void debug(String message, Object... args);

    // Methods that automatically include context
    void infoWithContext(String className, String methodName, String message, Object... args);
    void warnWithContext(String className, String methodName, String message, Object... args);
    void errorWithContext(String className, String methodName, String message, Object... args);
    void debugWithContext(String className, String methodName, String message, Object... args);
}
