package com.auth.service.dto;

import javax.annotation.Nullable;

public record OtpVerificationDto(
        @Nullable
        String password,
        String usernameOrEmail,
        String otp) {}
