package com.auth.service.dto;

import java.util.UUID;

import lombok.Data;

import java.util.List;

@Data
public class UserRoleDTO {
    private UUID id;
    private String role;
    private String description;
    private String status;
    private List<Long> permissionIds;
}
