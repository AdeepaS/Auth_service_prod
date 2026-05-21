package com.auth.service.dto;

import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record PinSetupDto(
        @NotNull(message = "User ID is required")
        UUID userId,

        @NotBlank(message = "PIN hash is required")
        String pinHash
) {}
