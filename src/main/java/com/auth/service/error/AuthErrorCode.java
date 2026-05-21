package com.auth.service.error;

/**
 * Central registry of error codes for the AUTH service.
 * Naming convention: <SERVICE>_<PROFILE>_<DOMAIN>_<SCENARIO>
 */
public enum AuthErrorCode {

    // Generic fallbacks
    AUTH_P1_UNCLASSIFIED_FAILURE,
    AUTH_P2_UNCLASSIFIED_FAILURE,

    // Authentication / token / RBAC
    AUTH_P1_TOKEN_INVALID,
    AUTH_P1_TOKEN_EXPIRED,
    AUTH_P1_ACCESS_DENIED;

    public String code() {
        return name();
    }
}
