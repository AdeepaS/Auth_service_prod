package com.auth.service.controller;

import java.util.UUID;

import com.auth.service.dto.*;
import com.auth.service.exception.ErrorCode;
import com.auth.service.logger.EnhancedLoggerAdapter;
import com.auth.service.logger.LoggerAdapter;
import com.auth.service.service.*;
import com.auth.service.service.AuthService;
import com.auth.service.service.impl.LoginAttemptServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Enumeration;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/Authservice")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final LoggerAdapter logger;
    private final EnhancedLoggerAdapter logger2;
    private final LogoutHandlerService logoutHandlerService;

    @Autowired
    private UserService userService;

    @Autowired
    private LoginAttemptServiceImpl loginAttemptServiceImpl;

    @Autowired
    private com.auth.service.repository.HotelRepo hotelRepo;

    @Value("${main.service.url:http://localhost:8081}")
    private String mainServiceUrl;

    @Autowired
    private org.springframework.web.client.RestTemplate restTemplate;

    // Admin secret key for admin operations
    @Value("${admin.secret.key}")
    private String adminSecretKey;

    private void logRequestHeaders(HttpServletRequest request) {
        logger.debug("Request Headers:");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            // Don't log sensitive headers
            if (isHeaderSensitive(headerName)) {
                logger.debug("{}: [REDACTED]", headerName);
            } else {
                String headerValue = request.getHeader(headerName);
                logger.debug("{}: {}", headerName, headerValue);
            }
        }
        String origin = request.getHeader("Origin");
        logger.debug("Origin header: {}", origin);
    }

    private boolean isHeaderSensitive(String headerName) {
        String lowerName = headerName.toLowerCase();
        return lowerName.contains("authorization") || 
               lowerName.contains("cookie") || 
               lowerName.contains("token") ||
               lowerName.contains("x-api-key");
    }

    // ==================== ACTIVE ENDPOINTS ====================

    @GetMapping("/auth/hotels")
    public ResponseEntity<ApiResponseDto<Object>> getHotelsForRegistration() {
        logger.info("[AuthController:getHotelsForRegistration] Fetching hotels list for signup");
        try {
            List<com.auth.service.entity.HotelEntity> hotels = hotelRepo.findAll();
            return ResponseEntity.ok(new ApiResponseDto<>(true, HttpStatus.OK.value(), "Hotels retrieved successfully", hotels));
        } catch (Exception e) {
            logger.error("[AuthController:getHotelsForRegistration] Error fetching hotels: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to fetch hotels list", null));
        }
    }

    @PostMapping({"/auth/sign-in", "/auth/login"})
    public ResponseEntity<ApiResponseDto<Object>> authenticateUser(
            @Valid @RequestBody AuthRequestDto authRequestDto,
            BindingResult bindingResult,
            HttpServletRequest request,
            HttpServletResponse response) {

        // Handle validation errors
        if (bindingResult.hasErrors()) {
            List<String> errorMessages = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            logger.error("[AuthController:authenticateUser] Validation errors: {}", errorMessages);
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Validation failed: " + String.join(", ", errorMessages),
                            null,
                            new ApiResponseDto.ErrorDetails2(4001)));
        }

        // Additional null check as safety measure
        if (authRequestDto.getUsername() == null || authRequestDto.getUsername().trim().isEmpty()) {
            logger.error("[AuthController:authenticateUser] Null or empty username received");
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Username or email is required",
                            null,
                            new ApiResponseDto.ErrorDetails2(4001)));
        }

        logger.info("Authentication attempt for user: {}", authRequestDto.getUsername());
        // ApiResponseDto<Object> authResponse = authService.authenticateUser(authRequestDto, response);
        ApiResponseDto<Object> authResponse = authService.authenticateUserWithoutOtp(authRequestDto, request,  response);
        
        // Return appropriate HTTP status code based on response success
        if (authResponse.isSuccess()) {
            return ResponseEntity.ok().body(authResponse);
        } else {
            return ResponseEntity.badRequest().body(authResponse);
        }
    }

    @PostMapping("/auth/sign-up")
    public ResponseEntity<ApiResponseDto<Object>> registerUser(
             @Valid @RequestBody UserRegistrationDto userRegistrationDto,
            BindingResult bindingResult,
            HttpServletResponse httpServletResponse,
            HttpServletRequest request) {

        logRequestHeaders(request);
        logger.info("[AuthController:registerUser] Signup Process Started for user: {}", userRegistrationDto.userEmail());

        // Handle validation errors
        if (bindingResult.hasErrors()) {
            List<String> errorMessages = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();

            logger.error("[AuthController:registerUser] Validation errors: {}", errorMessages);
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Validation failed", errorMessages, new ApiResponseDto.ErrorDetails2(4005)));
        }

        try {
            Object registeredUser = authService.registerUser(userRegistrationDto, request, httpServletResponse);
            return ResponseEntity.ok(new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "User registered successfully", registeredUser));
        } catch (ResponseStatusException e) {
            logger.warn("[AuthController:registerUser] Registration failed: {}", e.getReason());
            return ResponseEntity.status(e.getStatusCode())
                    .body(new ApiResponseDto<>(false, e.getStatusCode().value(),
                            e.getReason(), null, new ApiResponseDto.ErrorDetails2(4006)));
        } catch (Exception e) {
            logger.error("[AuthController:registerUser] Unexpected error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            "An unexpected error occurred", null, new ApiResponseDto.ErrorDetails2(5002)));
        }
    }

    @PostMapping("/auth/verify-otp-login")
    public ResponseEntity<ApiResponseDto<Object>> verifyOtpForLogin(
            @RequestBody VerifyOtpDto verifyOtpDto,
            HttpServletRequest request,
            HttpServletResponse response) {

        String usernameOrEmail = verifyOtpDto.getUsernameOrEmail();
        String otp = verifyOtpDto.getOtp();

        // Validate input
        if (usernameOrEmail == null || usernameOrEmail.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponseDto<>(
                            false,
                            ErrorCode.INVALID_REQUEST.getCode(),
                            "Username or email is required",
                            null,
                            new ApiResponseDto.ErrorDetails2(ErrorCode.INVALID_REQUEST.getCode())
                    )
            );
        }

        if (otp == null || otp.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponseDto<>(
                            false,
                            ErrorCode.INVALID_REQUEST.getCode(),
                            "OTP is required",
                            null,
                            new ApiResponseDto.ErrorDetails2(ErrorCode.INVALID_REQUEST.getCode())
                    )
            );
        }

        try {
            // Call the enhanced authentication service
            ApiResponseDto<Object> authResponse = authService.verifyOtpForAuthentication(
                    usernameOrEmail,
                    otp,
                    request,
                    response
            );

            // DEBUG: Verify cookies were set
            if (response.getHeader(HttpHeaders.SET_COOKIE) == null) {
                logger.warn("No Set-Cookie header in response for user: {}", usernameOrEmail);
            } else {
                logger.info("Set-Cookie header present for user: {}", usernameOrEmail);
            }

            // Return appropriate status code based on the response
            HttpStatus status = authResponse.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(authResponse);

        } catch (Exception e) {
            logger.error("Error during OTP verification: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ApiResponseDto<>(
                            false,
                            ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                            "An unexpected error occurred",
                            null,
                            new ApiResponseDto.ErrorDetails2(ErrorCode.INTERNAL_SERVER_ERROR.getCode())
                    )
            );
        }
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<ApiResponseDto<Object>> logout(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        logger2.info("logout starting....");
        logoutHandlerService.logout(request, response, authentication);
        return ResponseEntity.ok(
                new ApiResponseDto<>(true, HttpStatus.OK.value(),
                        "Logout successful", null)
        );
    }

    @PostMapping("/auth/refresh-token")
    public ResponseEntity<ApiResponseDto<Object>> getAccessToken(
            @RequestHeader(value = "authorizationrefreshtoken", required = false) String authorizationHeader,
            HttpServletRequest request) {

        logRequestHeaders(request);
        logger.info("[AuthController:getAccessToken] Refresh token request received. Header: {}", authorizationHeader);

        try {
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                logger.warn("[AuthController:getAccessToken] Missing or invalid Authorization header");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                                "Invalid or missing Authorization header",
                                null,
                                new ApiResponseDto.ErrorDetails2(4001)));
            }

            Object accessToken = authService.getAccessTokenUsingRefreshToken(request, authorizationHeader);
            return ResponseEntity.ok(new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "Access token refreshed successfully", accessToken));

        } catch (Exception e) {
            logger.error("[AuthController:getAccessToken] Unexpected error during token refresh", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            "An unexpected error occurred. Please try again later.",
                            null,
                            new ApiResponseDto.ErrorDetails2(5001)));
        }
    }

    // ==================== PIN ENDPOINTS ====================

    @PostMapping("/auth/api/setup-pin")
    public ResponseEntity<ApiResponseDto<Object>> setupPin(
            @Valid @RequestBody PinSetupDto pinSetupDto,
            BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            List<String> errors = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Validation failed: " + String.join(", ", errors), null));
        }

        ApiResponseDto<Object> response = authService.setupPin(pinSetupDto.userId(), pinSetupDto.pinHash());
        return ResponseEntity.status(response.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST).body(response);
    }

    @PostMapping("/auth/api/verify-pin")
    public ResponseEntity<ApiResponseDto<Object>> verifyPin(
            @Valid @RequestBody PinVerifyDto pinVerifyDto,
            BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            List<String> errors = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Validation failed: " + String.join(", ", errors), null));
        }

        ApiResponseDto<Object> response = authService.verifyPin(pinVerifyDto.userId(), pinVerifyDto.pinHash());
        HttpStatus status = response.isSuccess() ? HttpStatus.OK :
                response.getStatusCode() == HttpStatus.UNAUTHORIZED.value() ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(response);
    }

    // ==================== ADMIN ENDPOINTS ====================

    /**
     * Admin endpoint to delete a user by ID.
     * Requires X-Admin-Key header for authorization.
     * This endpoint performs cascade delete:
     * 1. Calls Main Service to delete children, devices, policies, etc.
     * 2. Deletes refresh tokens
     * 3. Deletes user record
     */
    @PostMapping("/admin/delete-user")
    public ResponseEntity<ApiResponseDto<Object>> adminDeleteUser(
            @RequestHeader(value = "X-Admin-Key", required = false) String adminKey,
            @RequestBody Map<String, Object> requestBody,
            HttpServletRequest request) {

        logger.info("[AuthController:adminDeleteUser] Admin delete user request received");

        // Validate admin key
        if (adminKey == null || !adminKey.equals(adminSecretKey)) {
            logger.warn("[AuthController:adminDeleteUser] Invalid or missing admin key");
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponseDto<>(false, HttpStatus.FORBIDDEN.value(),
                            "Forbidden: Invalid admin key", null));
        }

        // Extract user ID from request body
        Object userIdObj = requestBody.get("id");
        if (userIdObj == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "User ID is required", null));
        }

        UUID userId;
        try {
            if (userIdObj instanceof Integer) {
                userId = java.util.UUID.fromString(userIdObj.toString());
            } else if (userIdObj instanceof UUID) {
                userId = (UUID) userIdObj;
            } else {
                userId = UUID.fromString(userIdObj.toString());
            }
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Invalid user ID format", null));
        }

        logger.info("[AuthController:adminDeleteUser] Starting cascade delete for user ID: {}", userId);

        Map<String, Object> deletionSummary = new java.util.LinkedHashMap<>();
        deletionSummary.put("userId", userId);

        try {
            // Step 1: Call Main Service to cascade delete user data (children, devices, etc.)
            boolean mainServiceDeleteSuccess = cascadeDeleteFromMainService(userId, adminKey);
            deletionSummary.put("mainServiceDataDeleted", mainServiceDeleteSuccess);
            
            if (!mainServiceDeleteSuccess) {
                logger.warn("[AuthController:adminDeleteUser] Main Service cascade delete failed, continuing with Auth Service deletion");
            }

            // Step 2: Delete user from Auth Service (this will cascade delete refresh tokens due to JPA relationship)
            ApiResponseDto<String> result = userService.deleteUser(userId);
            
            if (result.isSuccess()) {
                deletionSummary.put("authServiceUserDeleted", true);
                deletionSummary.put("message", "User and all related data deleted successfully");
                
                logger.info("[AuthController:adminDeleteUser] User {} deleted successfully. Summary: {}", userId, deletionSummary);
                
                return ResponseEntity.ok(new ApiResponseDto<>(true, HttpStatus.OK.value(),
                        "User deleted successfully", deletionSummary));
            } else {
                deletionSummary.put("authServiceUserDeleted", false);
                deletionSummary.put("error", result.getMessage());
                
                return ResponseEntity.status(result.getStatusCode())
                        .body(new ApiResponseDto<>(false, result.getStatusCode(),
                                result.getMessage(), deletionSummary));
            }
        } catch (Exception e) {
            logger.error("[AuthController:adminDeleteUser] Error deleting user: {}", e.getMessage(), e);
            deletionSummary.put("error", e.getMessage());
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            "Error deleting user: " + e.getMessage(), deletionSummary));
        }
    }

    /**
     * Helper method to call Main Service cascade delete endpoint
     */
    private boolean cascadeDeleteFromMainService(UUID userId, String adminKey) {
        try {
            String url = mainServiceUrl + "/router-backend/user/cascade-delete";
            logger.info("[AuthController:cascadeDeleteFromMainService] Calling Main Service: {}", url);

            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.set("X-Admin-Key", adminKey);
            headers.set("Content-Type", "application/json");

            Map<String, Object> body = new java.util.HashMap<>();
            body.put("userId", userId);

            org.springframework.http.HttpEntity<Map<String, Object>> entity = 
                new org.springframework.http.HttpEntity<>(body, headers);

            org.springframework.http.ResponseEntity<Map> response = restTemplate.exchange(
                url,
                org.springframework.http.HttpMethod.POST,
                entity,
                Map.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Boolean success = (Boolean) response.getBody().get("success");
                logger.info("[AuthController:cascadeDeleteFromMainService] Main Service response: {}", response.getBody());
                return success != null && success;
            }
            
            return false;
        } catch (Exception e) {
            logger.error("[AuthController:cascadeDeleteFromMainService] Error calling Main Service: {}", e.getMessage());
            return false;
        }
    }

    // ==================== UNUSED ENDPOINTS (COMMENTED OUT) ====================

    // ==================== OTP & PASSWORD ENDPOINTS ====================

    //Password based registration
    @PostMapping("/auth/password/sign-up")
    public ResponseEntity<ApiResponseDto<Object>> registerWithPassword(
            @RequestBody @Valid PasswordRegistrationDto registrationDto,
            BindingResult bindingResult,
            HttpServletRequest request) {

        logRequestHeaders(request);
        logger.info("[AuthController:registerWithPassword] Password signup for: {}", registrationDto.userEmail());

        // Validation handling
        if (bindingResult.hasErrors()) {
            List<String> errors = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            logger.error("[AuthController:registerWithPassword] Validation errors: {}", errors);
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Validation failed", errors, new ApiResponseDto.ErrorDetails2(4007)));
        }

        ApiResponseDto<Object> response = authService.registerWithPassword(registrationDto, request);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/auth/password/sign-in")
    public ResponseEntity<ApiResponseDto<Object>> loginWithPassword(
            @RequestBody PasswordLoginDto loginDto,
            HttpServletRequest request) {

        ApiResponseDto<Object> response = authService.authenticateWithPassword(
                loginDto.usernameOrEmail(),
                loginDto.password(),
                request
        );

        return ResponseEntity.status(response.getStatusCode()).body(response);
    }



    @PostMapping("/auth/first-login-reset")
    public ResponseEntity<ApiResponseDto<?>> firstLoginResetPassword(
            @Valid @RequestBody FirstLoginPasswordResetDto resetDto) {

        ApiResponseDto<String> result = authService.firstLoginResetPassword(resetDto);
        logger.info("[AuthController:authorize] First Login Response: {}", result);
        return ResponseEntity.ok().body(result);
    }

    @PostMapping("/auth/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        try {
            ApiResponseDto<String> result = authService.reSendOtp(forgetPasswordDto.getUsernameOrEmail());
            return ResponseEntity.status(result.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST).body(result);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to resend OTP. Please try again.");
        }
    }

    @PostMapping("/auth/forgot-password")
    public ResponseEntity<ApiResponseDto<String>> forgotPassword(@RequestBody ForgetPasswordDto forgetPasswordDto) {
        String usernameOrEmail = forgetPasswordDto.getUsernameOrEmail();

        if (usernameOrEmail == null || usernameOrEmail.trim().isEmpty()) {
            ApiResponseDto<String> response = new ApiResponseDto<>(
                    false,
                    HttpStatus.BAD_REQUEST.value(),
                    "Username or email is required.",
                    null,
                    new ApiResponseDto.ErrorDetails2(1000)
            );
            return ResponseEntity.badRequest().body(response);
        }

        ApiResponseDto<String> result = authService.initiatePasswordReset(usernameOrEmail);
        return ResponseEntity.status(result.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST).body(result);
    }

    @PostMapping("/auth/verify-otp")
    public ResponseEntity<ApiResponseDto<String>> verifyOtp(@RequestBody VerifyOtpDto verifyOtpDto) {
        String usernameOrEmail = verifyOtpDto.getUsernameOrEmail();
        String otp = verifyOtpDto.getOtp();

        if (usernameOrEmail == null || usernameOrEmail.trim().isEmpty()) {
            ApiResponseDto<String> response = new ApiResponseDto<>(
                    false,
                    1000,
                    "Username or email is required.",
                    null
            );
            return ResponseEntity.badRequest().body(response);
        }

        if (otp == null || otp.trim().isEmpty()) {
            ApiResponseDto<String> response = new ApiResponseDto<>(
                    false,
                    1001,
                    "OTP is required.",
                    null
            );
            return ResponseEntity.badRequest().body(response);
        }

        ApiResponseDto<Object> result = authService.verifyOtp(new OtpVerificationDto(null, usernameOrEmail, otp), null, null);
        return ResponseEntity.status(result.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST).body(new ApiResponseDto<>(result.isSuccess(), result.getStatusCode(), result.getMessage(), null));
    }

    @PostMapping("/auth/reset-forgotten-password")
    public ResponseEntity<ApiResponseDto<String>> resetForgottenPassword(@RequestBody ResetPasswordDto resetPasswordDto) {
        String usernameOrEmail = resetPasswordDto.getUsernameOrEmail();
        String otp = resetPasswordDto.getOtp();
        String newPassword = resetPasswordDto.getNewPassword();
        String confirmPassword = resetPasswordDto.getConfirmPassword();

        if (usernameOrEmail == null || usernameOrEmail.trim().isEmpty()) {
            ApiResponseDto<String> response = new ApiResponseDto<>(
                    false,
                    1000,
                    "Username or email is required.",
                    null
            );
            return ResponseEntity.badRequest().body(response);
        }

        if (otp == null || otp.trim().isEmpty()) {
            ApiResponseDto<String> response = new ApiResponseDto<>(
                    false,
                    1001,
                    "OTP is required.",
                    null
            );
            return ResponseEntity.ok().body(response);
        }

        if (newPassword == null || newPassword.trim().isEmpty()) {
            ApiResponseDto<String> response = new ApiResponseDto<>(
                    false,
                    1002,
                    "New password is required.",
                    null
            );
            return ResponseEntity.ok().body(response);
        }

        if (!newPassword.equals(confirmPassword)) {
            ApiResponseDto<String> response = new ApiResponseDto<>(
                    false,
                    1003,
                    "Passwords do not match.",
                    null
            );
            return ResponseEntity.ok().body(response);
        }

        ApiResponseDto<String> result = authService.resetForgottenPassword(usernameOrEmail, otp, newPassword);
        return ResponseEntity.status(result.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST).body(result);
    }
    


    @PostMapping("/auth/setup-password")
    public ResponseEntity<ApiResponseDto<Object>> setupPassword(
            @Valid @RequestBody PasswordSetupDto dto,
            BindingResult bindingResult) {
        
        if (bindingResult.hasErrors()) {
            List<String> errors = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            return ResponseEntity.badRequest()
                    .body(new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                            "Validation failed: " + String.join(", ", errors), null));
        }

        ApiResponseDto<Object> response = authService.setupPassword(dto);
        return ResponseEntity.status(response.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST).body(response);
    }
}