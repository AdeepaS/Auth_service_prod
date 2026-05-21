package com.auth.service.exception;

public class LdapException extends RuntimeException {

    private final ErrorCode errorCode;

    private LdapException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    // LdapConnectionException specific method
    public static LdapException connectionFailed(String message) {
        return new LdapException(ErrorCode.LDAP_CONNECTION_FAILED, "LDAP connection failed: " + message);
    }

    // LdapAuthenticationFailedException specific method
    public static LdapException authenticationFailed(String message) {
        return new LdapException(ErrorCode.LDAP_AUTHENTICATION_FAILED, "LDAP authentication failed: " + message);
    }

    // Optional: Invalid credentials (generic example)
    public static LdapException invalidCredentials(String message) {
        return new LdapException(ErrorCode.LDAP_INVALID_CREDENTIALS, "LDAP invalid credentials: " + message);
    }
}
