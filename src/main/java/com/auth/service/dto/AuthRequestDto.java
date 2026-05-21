package com.auth.service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthRequestDto {
    @NotBlank(message = "Username or email is required")
    @JsonProperty("usernameOrEmail")
    private String usernameOrEmail;

    private String password;

    // Support alternative field names for backward compatibility
    @JsonProperty("email")
    public void setEmail(String email) {
        if (this.usernameOrEmail == null || this.usernameOrEmail.trim().isEmpty()) {
            this.usernameOrEmail = email;
        }
    }

    @JsonProperty("username")
    public void setUsername(String username) {
        if (this.usernameOrEmail == null || this.usernameOrEmail.trim().isEmpty()) {
            this.usernameOrEmail = username;
        }
    }

    public String getUsername() {
        return usernameOrEmail;
    }

    public String getUsernameOrEmail() {
        return usernameOrEmail;
    }

    public void setUsernameOrEmail(String usernameOrEmail) {
        this.usernameOrEmail = usernameOrEmail;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

