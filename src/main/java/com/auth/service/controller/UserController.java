package com.auth.service.controller;

import java.util.UUID;

import com.auth.service.dto.*;
import com.auth.service.logger.EnhancedLoggerAdapter;
import com.auth.service.service.AuthService;
import com.auth.service.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;


@RestController
@RequestMapping("/Authservice/auth/api")
public class UserController {
    private final UserService userService;
    private final AuthService authService;

    @Autowired
    private EnhancedLoggerAdapter logger;

    @Autowired
    public UserController(UserService userService, AuthService authService, EnhancedLoggerAdapter logger) {
        this.userService = userService;
        this.authService = authService;
        this.logger = logger;
    }

    @PostMapping("/create/user")
    public ResponseEntity<ApiResponseDto<Object>> createUser(@RequestBody UserRegistrationDto userRegistrationDto) {
        Object registeredUser = userService.createUser(userRegistrationDto);
        logger.info("User registered successfully: {}", registeredUser);
        return ResponseEntity.ok(new ApiResponseDto<>(
                true,
                HttpStatus.OK.value(),
                "User registered successfully",
                registeredUser
        ));
    }

    @PostMapping("/update/user")
    public ResponseEntity<ApiResponseDto<UserResponseDTO>> updateUser(@RequestBody UserDto userDTO) {
        logger.info("Updating user with ID: {}", userDTO.getId());
        ApiResponseDto<UserResponseDTO> response = userService.updateUser(userDTO);
        logger.info("Update response for user ID {}: {}", userDTO.getId(), response);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponseDto<UserResponseDTO>> getUserById(@PathVariable UUID id) {
        logger.info("Fetching user with ID: {}", id);
        ApiResponseDto<UserResponseDTO> response = userService.getUserById(id);
        logger.info("Fetched user: {}", response.getData());
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/update/firstLoginReset")
    public ResponseEntity<ApiResponseDto<?>> firstLoginResetPassword(
            @Valid @RequestBody FirstLoginPasswordResetDto resetDto) {

        ApiResponseDto<String> result = authService.firstLoginResetPassword(resetDto);
        logger.info("[AuthController:authorize] First Login Response: {}", result);
        return ResponseEntity.ok().body(result);
    }

    @GetMapping("/email/{emailId}")
    public ResponseEntity<ApiResponseDto<UserResponseDTO>> getUserByEmail(@PathVariable String emailId) {
        logger.info("Fetching user by email: {}", emailId);
        ApiResponseDto<UserResponseDTO> response = userService.getUserByEmail(emailId);
        logger.info("Fetched user for email {}: {}", emailId, response.getData());
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/view/allUsers")
    public ResponseEntity<ApiResponseDto<List<UserResponseDTO>>> getAllUsers() {
        logger.info("Fetching all users");
        ApiResponseDto<List<UserResponseDTO>> response = userService.getAllUsers();
        logger.info("Number of users fetched: {}", response.getData().size());
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/delete/user")
    public ResponseEntity<ApiResponseDto<String>> deleteUser(@RequestBody  UserDto userDTO) {
        logger.info("Attempting to delete user with ID: {}", userDTO.getId());
        java.util.UUID userId = userDTO.getId();
        ApiResponseDto<String> response = userService.deleteUser(userId);
        logger.info("User deletion status: {}", response.getMessage());
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/update/userPassword")
    public ResponseEntity<ApiResponseDto<String>> resetPassword(
            @Valid @RequestBody PasswordResetDto passwordResetDto) {

        ApiResponseDto<String> result = userService.resetPassword(passwordResetDto);
        return ResponseEntity.status(result.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST)
                .body(result);
    }

}