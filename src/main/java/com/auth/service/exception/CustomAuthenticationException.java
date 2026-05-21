package com.auth.service.exception;

public class CustomAuthenticationException extends RuntimeException {
    private final ErrorCode errorCode;

    public CustomAuthenticationException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
