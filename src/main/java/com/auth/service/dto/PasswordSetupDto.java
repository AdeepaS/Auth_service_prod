package com.auth.service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PasswordSetupDto {
    @NotBlank(message = "Token is required")
    private String token;

    @NotBlank(message = "Password is required")
    private String password;
}
