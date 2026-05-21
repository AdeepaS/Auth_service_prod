package com.auth.service.dto;

public record PasswordLoginDto(
        String usernameOrEmail,
        String password
) {}
