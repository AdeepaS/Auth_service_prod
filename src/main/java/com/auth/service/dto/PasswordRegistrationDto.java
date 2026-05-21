package com.auth.service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record PasswordRegistrationDto(
        String userMobileNo,

        @NotEmpty(message = "User email must not be empty")
        @Email(message = "Invalid email format")
        String userEmail,

        String password  // Add password field
) {}
