package com.auth.service.controller;

import com.auth.service.dto.ApiResponseDto;
import com.auth.service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/Authservice/admin/api")
public class AdminController {

    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    // @PreAuthorize("hasRole('ADMIN')") // Enable if Role-Based Access Control is required
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @GetMapping("/users/pending")
    public ResponseEntity<ApiResponseDto<java.util.List<com.auth.service.dto.UserResponseDTO>>> getPendingTechnicians() {
        ApiResponseDto<java.util.List<com.auth.service.dto.UserResponseDTO>> response = userService.getPendingTechnicians();
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @PutMapping("/users/{id}/approve")
    public ResponseEntity<ApiResponseDto<String>> approveUser(@PathVariable UUID id) {
        ApiResponseDto<String> response = userService.approveUser(id);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/users/internal")
    public ResponseEntity<ApiResponseDto<String>> createInternalUser(
            @RequestBody com.auth.service.dto.InternalUserCreateDto createDto,
            org.springframework.security.core.Authentication authentication) {
        // Creator email is obtained from the JWT token authentication object
        String creatorEmail = authentication.getName();
        ApiResponseDto<String> response = userService.createInternalUser(createDto, creatorEmail);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }
}
