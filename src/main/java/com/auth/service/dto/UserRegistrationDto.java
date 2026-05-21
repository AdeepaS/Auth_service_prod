package com.auth.service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record UserRegistrationDto(
        @NotEmpty(message = "User name must not be empty")
        String userName,

        @NotEmpty(message = "User email must not be empty")
        @Email(message = "Invalid email format")
        String userEmail,

        String userMobileNo,

        @NotEmpty(message = "Password must not be empty")
        String userPassword,

        java.util.UUID hotelId
) {}
