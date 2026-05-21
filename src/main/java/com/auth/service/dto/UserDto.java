package com.auth.service.dto;

import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private UUID id;
    private String name;
    private String email;
    private String mobileNumber;
    private String address;
    private String role;
    private String passwordHash;
    private boolean isVerified;
    private Boolean isActive;
}
