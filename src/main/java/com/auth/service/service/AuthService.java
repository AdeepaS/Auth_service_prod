package com.auth.service.service;

import java.util.UUID;

import com.auth.service.dto.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

public interface AuthService {

    ApiResponseDto<Object> authenticateUser(AuthRequestDto authRequestDto, HttpServletResponse response);

    ApiResponseDto<Object> authenticateUserWithoutOtp(AuthRequestDto authRequestDto, HttpServletRequest request, HttpServletResponse response);

    AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response);

    Object getAccessTokenUsingRefreshToken(HttpServletRequest request, String authorizationHeader);

    AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto, HttpServletRequest request, HttpServletResponse httpServletResponse);

    String GetUserRole(String token);

    ApiResponseDto<Object> verifyOtp(OtpVerificationDto otpVerificationDto, HttpServletRequest request, HttpServletResponse httpServletResponse);

     ApiResponseDto<String> reSendOtp(String usernameOrEmail);

//    ApiResponseDto<String> resetPassword(PasswordResetDto passwordResetDto);

    public ApiResponseDto<String> firstLoginResetPassword(FirstLoginPasswordResetDto resetDto);

    ApiResponseDto<String> initiatePasswordReset(String usernameOrEmail);
    ApiResponseDto<String> verifyOtp(String usernameOrEmail, String otp);
    ApiResponseDto<String> resetForgottenPassword(String usernameOrEmail, String otp, String newPassword);
    ApiResponseDto<Object> authenticateWithPassword(
            String usernameOrEmail,
            String password,
            HttpServletRequest request);
    ApiResponseDto<Object> registerWithPassword(PasswordRegistrationDto dto, HttpServletRequest request);
    ApiResponseDto<Object> verifyOtpForAuthentication(String usernameOrEmail, String otp, HttpServletRequest request, HttpServletResponse response);

    ApiResponseDto<Object> setupPin(UUID userId, String pinHash);

    ApiResponseDto<Object> verifyPin(UUID userId, String pinHash);
    
    ApiResponseDto<Object> setupPassword(PasswordSetupDto dto);
}
