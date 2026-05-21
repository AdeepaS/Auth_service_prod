package com.auth.service.service;

import java.util.UUID;

import com.auth.service.dto.*;

import java.util.List;

public interface UserService {
    ApiResponseDto<UserResponseDTO> createUser(UserRegistrationDto userDTO);

    ApiResponseDto<UserResponseDTO> updateUser(UserDto userDTO);

    ApiResponseDto<UserResponseDTO> getUserById(UUID id);

    ApiResponseDto<UserResponseDTO> getUserByEmail(String emailId);

    ApiResponseDto<List<UserResponseDTO>> getAllUsers();

    ApiResponseDto<String> deleteUser(UUID id);

    ApiResponseDto<String> changePassword(UUID userId, String oldPassword, String newPassword);

    ApiResponseDto<String> verifyOtp(String emailId, String otp);

    ApiResponseDto<String> resetPassword(PasswordResetDto passwordResetDto);

    ApiResponseDto<String> approveUser(UUID id);

    ApiResponseDto<String> createInternalUser(InternalUserCreateDto createDto, String creatorEmail);
}