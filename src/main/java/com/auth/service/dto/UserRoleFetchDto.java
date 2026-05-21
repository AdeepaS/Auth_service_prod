package com.auth.service.dto;

import java.util.UUID;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class UserRoleFetchDto {

    private UUID id;
    private String role;
    private String description;
    private String status;
    private Map<Long, String> permissionMap;
}
