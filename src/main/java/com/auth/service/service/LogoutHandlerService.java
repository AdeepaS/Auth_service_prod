package com.auth.service.service;

import org.springframework.security.core.Authentication;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public interface LogoutHandlerService extends LogoutHandler {

    void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication);
}
