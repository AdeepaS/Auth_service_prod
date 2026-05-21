package com.auth.service.service.impl;

import com.auth.service.service.AuthenticationStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class DatabaseAuthenticationStrategy implements AuthenticationStrategy {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public Authentication authenticate(String username, String password) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}

