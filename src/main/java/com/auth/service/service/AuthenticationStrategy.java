package com.auth.service.service;

import org.springframework.security.core.Authentication;

public interface AuthenticationStrategy {

    Authentication authenticate(String username, String password);
}
