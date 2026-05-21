package com.auth.service.exception;

public class EmailException extends RuntimeException {

    private final ErrorCode errorCode;

    private EmailException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    // Email sending failed
    public static EmailException sendingFailed(String message) {
        return new EmailException(ErrorCode.EMAIL_SENDING_FAILED, "Email sending failed: " + message);
    }

    // Invalid email address
    public static EmailException invalidAddress(String message) {
        return new EmailException(ErrorCode.EMAIL_INVALID_ADDRESS, "Invalid email address: " + message);
    }

    // Email server error
    public static EmailException serverError(String message) {
        return new EmailException(ErrorCode.EMAIL_SERVER_ERROR, "Email server error: " + message);
    }

    // Email content error
    public static EmailException contentError(String message) {
        return new EmailException(ErrorCode.EMAIL_CONTENT_ERROR, "Email content error: " + message);
    }
}

