package com.auth.service.dto;

public class PermissionRequestDto {

    private String role;      // The user's role (e.g., "ROLE_ADMIN", "ROLE_USER")
    private String resource;  // The API endpoint or resource (e.g., "/add_appointment")
    private String action;    // The HTTP method (e.g., "POST", "GET")

    // Constructors
    public PermissionRequestDto() {}

    public PermissionRequestDto(String role, String resource, String action) {
        this.role = role;
        this.resource = resource;
        this.action = action;
    }

    // Getters and Setters
    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    @Override
    public String toString() {
        return "PermissionRequestDto{" +
                "role='" + role + '\'' +
                ", resource='" + resource + '\'' +
                ", action='" + action + '\'' +
                '}';
    }
}
