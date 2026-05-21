package com.auth.service.service.impl;

import java.util.UUID;

import com.auth.service.dto.*;
import com.auth.service.entity.UserEntity;
import java.util.UUID;
import com.auth.service.logger.EnhancedLoggerAdapter;
import com.auth.service.mapper.UserInfoMapper;
import com.auth.service.repository.UserRepo;
import com.auth.service.service.EmailService;
import com.auth.service.service.UserService;
import com.auth.service.util.PasswordGenerator;
import com.auth.service.util.UserUtil;
import com.auth.service.util.OtpUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    @Value("${authentication.method}")
    private String authenticationMethod;

    @Value("${authentication.password-length:12}")
    private int passwordLength;
    private final UserRepo userRepository;

    private final UserUtil userUtil;
    private final PasswordEncoder passwordEncoder;
    
    @Value("${main.service.url:http://localhost:3000}")
    private String mainServiceUrl;


    @Autowired
    private final EnhancedLoggerAdapter logger;

    @Autowired
    private final UserInfoMapper userInfoMapper;

    @Autowired
    private PasswordGenerator passwordGenerator;

    private final UserRepo userInfoRepo;

    @Autowired
    private final EmailService emailService;

    @Autowired
    private OtpUtil otpUtil;

    @Autowired
    public UserServiceImpl(UserRepo userRepository, UserUtil userUtil,
                           PasswordEncoder passwordEncoder, EnhancedLoggerAdapter logger, UserInfoMapper userInfoMapper, UserRepo userInfoRepo, EmailService emailService) {
        this.userRepository = userRepository;
        this.userUtil = userUtil;
        this.passwordEncoder = passwordEncoder;
        this.logger = logger;
        this.userInfoMapper = userInfoMapper;
        this.userInfoRepo = userInfoRepo;
        this.emailService = emailService;
    }

    @Override
    @Transactional
    public ApiResponseDto<UserResponseDTO> createUser(UserRegistrationDto userDTO) {
        logger.info("Creating new user");
        logger.debug("Creating user with email: {}", maskEmail(userDTO.userEmail()));
        try {
            // Check if user with the same email already exists
            if (userRepository.existsByEmail(userDTO.userEmail())) {
                logger.warn("Attempted to create user with email that already exists");
                logger.debug("Duplicate email: {}", maskEmail(userDTO.userEmail()));
                return new ApiResponseDto<>(false, HttpStatus.CONFLICT.value(),
                        "User with this email already exists", null);
            }


            


            // Convert DTO to entity
            UserEntity userDetailsEntity = userInfoMapper.convertToEntity(userDTO);

            if (userDTO.userPassword() != null && !userDTO.userPassword().isEmpty()) {
                userDetailsEntity.setPasswordHash(passwordEncoder.encode(userDTO.userPassword()));
            } else {
                String randomPassword = passwordGenerator.generateRandomPassword(passwordLength);
                userDetailsEntity.setPasswordHash(passwordEncoder.encode(randomPassword));
                sendPasswordEmail(userDetailsEntity.getEmail(), userDetailsEntity.getEmail(), randomPassword);
            }
            
            // Generate and set OTP for verification
            String otp = otpUtil.generateOtp();
            userDetailsEntity.setOtp(otp);
            userDetailsEntity.setOtpExpiry(otpUtil.generateOtpExpiry());
            
            // Set initial status to UNVERIFIED for safety
            userDetailsEntity.setAccountStatus(com.auth.service.entity.AccountStatus.UNVERIFIED);
            userDetailsEntity.setIsActive(false);

            // Send OTP email
            emailService.sendOtpEmail(userDetailsEntity.getEmail(), otp);
            logger.info("OTP sent to newly created user: {}", userDetailsEntity.getEmail());

            // Fetch hotel if provided
            if (userDTO.hotelId() != null) {
                com.auth.service.entity.HotelEntity proxyHotel = new com.auth.service.entity.HotelEntity();
                proxyHotel.setId(userDTO.hotelId());
                userDetailsEntity.setHotel(proxyHotel);
            }

            // Save user
            UserEntity savedUserDetails = userInfoRepo.save(userDetailsEntity);


            logger.info("[AuthService:registerUser] User successfully registered");
            logger.debug("[AuthService:registerUser] User ID: {}", savedUserDetails.getId());

            // Map to response DTO
            UserResponseDTO user = mapUserToResponseDTO(savedUserDetails);

            logger.info("User created with ID: {}", user.getId());
            return new ApiResponseDto<>(true, HttpStatus.CREATED.value(),
                    "User created successfully", user);
        } catch (Exception e) {
            logger.error("Error creating user: {}", e.getMessage(), e);
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while creating the user: " + e.getMessage(), null);
        }
    }

    @Override
    @Transactional
    public ApiResponseDto<UserResponseDTO> updateUser(UserDto userDTO) {
        logger.info("Updating user with ID: {}", userDTO.getId());
        try {
            // Find the existing user
            logger.debug("Updating user: {}", maskUserDto(userDTO));
            Optional<UserEntity> userOptional = userRepository.findById(userDTO.getId());
            if (userOptional.isEmpty()) {
                logger.warn("User not found with ID: {}", userDTO.getId());
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with ID: " + userDTO.getId(), null);
            }

            UserEntity existingUser = userOptional.get();

//            // Only update fields that are not null in the DTO
//            if (userDTO.getName() != null) {
//                // Check if username is being changed and if new username already exists
//                if (!existingUser.getName().equals(userDTO.getName())) {
//                    if (userRepository.existsByUserName(userDTO.getName())) {
//                        logger.warn("Username/email conflict during update for user ID: {}", userDTO.getId());
//                        return new ApiResponseDto<>(false, HttpStatus.CONFLICT.value(),
//                                "Username already exists", null);
//                    }
//                    existingUser.setName(userDTO.getName());
//                }
//            }

            if (userDTO.getEmail() != null) {
                // Check if email is being changed and if new email already exists
                if (!existingUser.getEmail().equals(userDTO.getEmail())) {
                    if (userRepository.existsByEmail(userDTO.getEmail())) {
                        logger.warn("Username/email conflict during update for user ID: {}", userDTO.getId());
                        return new ApiResponseDto<>(false, HttpStatus.CONFLICT.value(),
                                "User with this email already exists", null);
                    }
                    existingUser.setEmail(userDTO.getEmail());
                }
            }

            if (userDTO.getMobileNumber() != null) {
                existingUser.setMobileNumber(userDTO.getMobileNumber());
            }


            // Update status if provided (assuming status can be null)
            if (userDTO.getIsActive() != null) {
                existingUser.setIsActive(userDTO.getIsActive());
            }


            // Save the updated user
            existingUser = userRepository.save(existingUser);

            // Map to response DTO
            UserResponseDTO responseDTO = mapUserToResponseDTO(existingUser);

            logger.info("User updated successfully with ID: {}", existingUser.getId());
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "User updated successfully", responseDTO);
        } catch (Exception e) {
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while updating the user: " + e.getMessage(), null);
        }
    }

    @Override
    public ApiResponseDto<UserResponseDTO> getUserById(UUID id) {
        logger.info("Fetching user by ID: {}", id);
        try {
            Optional<UserEntity> userOptional = userRepository.findById(id);
            if (userOptional.isEmpty()) {
                logger.warn("User not found with ID: {}", id);
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with ID: " + id, null);
            }

            UserEntity user = userOptional.get();
            UserResponseDTO responseDTO = mapUserToResponseDTO(user);

            logger.info("User fetched successfully with ID: {}", id);
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "User retrieved successfully", responseDTO);
        } catch (Exception e) {
            logger.error("Error fetching user by ID: {}", e.getMessage(), e);
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while retrieving the user: " + e.getMessage(), null);
        }
    }

    @Override
    public ApiResponseDto<UserResponseDTO> getUserByEmail(String emailId) {
        logger.debug("Fetching user by email: {}", maskEmail(emailId));
        try {
            Optional<UserEntity> userOptional = userRepository.findByEmail(emailId);
            if (userOptional.isEmpty()) {
                logger.warn("User not found with provided email");
                logger.debug("User not found: {}", maskEmail(emailId));
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with email: " + emailId, null);
            }

            UserEntity user = userOptional.get();
            UserResponseDTO responseDTO = mapUserToResponseDTO(user);

            logger.info("User fetched successfully");
            logger.debug("Fetched user: {}", maskEmail(emailId));
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "User retrieved successfully", responseDTO);
        } catch (Exception e) {
            logger.error("Error fetching user by email: {}", e.getMessage() );
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while retrieving the user: " + e.getMessage(), null);
        }
    }

    @Override
    public ApiResponseDto<List<UserResponseDTO>> getAllUsers() {

        String correlationId = userUtil.getCorrelationIdFromAuthentication();
        String sessionId = userUtil.getSessionIdFromAuthentication();
        java.util.UUID userId = userUtil.getId();

        logger.info("Starting to fetch all user roles: {}", userId);

        logger.info("Fetching starting.... ");
        try {
            List<UserEntity> users = userRepository.findAll();
            List<UserResponseDTO> responseDTOs = users.stream()
                    .map(this::mapUserToResponseDTO)
                    .collect(Collectors.toList());

            logger.info("Successfully fetched all users. Count: {}", responseDTOs.size());
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "Users retrieved successfully", responseDTOs);
        } catch (Exception e) {
            logger.error("Error while fetching users: {} ",e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while retrieving users: " + e.getMessage(), null);
        }
    }

    @Override
    @Transactional
    public ApiResponseDto<String> deleteUser(UUID id) {
        logger.info("Deleting user with ID: {}", id);
        try {
            Optional<UserEntity> userOptional = userRepository.findById(id);
            if (userOptional.isEmpty()) {
                logger.warn("User not found for deletion with ID: {}", id);
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with ID: " + id, null);
            }

            userRepository.deleteById(id);

            logger.info("User deleted with ID: {}", id);
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "User deleted successfully", null);
        } catch (Exception e) {
            logger.error("Error deleting user with ID: {} - {}", id, e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while deleting the user: " + e.getMessage(), null);
        }
    }

    @Override
    @Transactional
    public ApiResponseDto<String> changePassword(UUID userId, String oldPassword, String newPassword) {
        logger.info("Changing password for user ID: {}", userId);
        try {
            Optional<UserEntity> userOptional = userRepository.findById(userId);
            if (userOptional.isEmpty()) {
                logger.warn("Incorrect current password for user ID: {}", userId);
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with ID: " + userId, null);
            }

            UserEntity user = userOptional.get();



            // Update password

            userRepository.save(user);

            logger.info("Password changed successfully for user ID: {}", userId);
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "Password changed successfully", null);
        } catch (Exception e) {
            logger.error("Error changing password for user ID: {} {}", userId, e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while changing the password: " + e.getMessage(), null);
        }
    }


    @Override
    public ApiResponseDto<String> resetPassword(PasswordResetDto passwordResetDto) {
        UUID userId = userUtil.getId();
        try {
            logger.info("Password reset requested for user ID: {}", userId);

            // Validate passwords match
            if (!passwordResetDto.newPassword().equals(passwordResetDto.confirmPassword())) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                        "New password and confirm password do not match", null);
            }

            // Find user by email
            Optional<UserEntity> userOptional = userInfoRepo.findById(userId);
            if (userOptional.isEmpty()) {
                logger.warn("User not found for password reset: {}", userId);
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with user Id: " + userId, null);
            }

            UserEntity user = userOptional.get();

            // Check if LDAP authentication is enabled
            boolean isLdapAuth = "ldap".equalsIgnoreCase(authenticationMethod);
            if (isLdapAuth) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                        "Password reset is not available for LDAP users. Please contact your system administrator.", null);
            }



            // Update password




            userInfoRepo.save(user);

            logger.info("[AuthService:resetPassword] Password reset successful");
            logger.debug("[AuthService:resetPassword] User ID: {}", user.getId());
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "Password reset successful", null);

        } catch (Exception e) {
            logger.error("Error resetting password for user: {}", userId, e);
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while resetting the password: " + e.getMessage(), null);
        }
    }

    @Override
    @Transactional
    public ApiResponseDto<String> verifyOtp(String emailId, String otp) {
        logger.debug("Verifying OTP for email: {}", maskEmail(emailId));
        try {
            Optional<UserEntity> userOptional = userRepository.findByEmail(emailId);
            if (userOptional.isEmpty()) {
                logger.warn("Invalid OTP verification");
                logger.debug("Invalid OTP for: {}", maskEmail(emailId));
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with email: " + emailId, null);
            }

            UserEntity user = userOptional.get();

            // Verify OTP
            if (user.getOtp() == null || !user.getOtp().equals(otp)) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                        "Invalid OTP", null);
            }

            // Check if OTP is expired
            if (user.getOtpExpiry() == null || LocalDateTime.now().isAfter(user.getOtpExpiry())) {
                logger.warn("Expired OTP for email: {}", emailId);
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                        "OTP has expired", null);
            }

            // Clear OTP
            user.setOtp(null);
            user.setOtpExpiry(null);
            userRepository.save(user);

            logger.info("OTP verified successfully");
            logger.debug("OTP verified for: {}", maskEmail(emailId));
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "OTP verified successfully", null);
        } catch (Exception e) {
            logger.error("Error verifying OTP for email: {} {}", emailId, e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while verifying the OTP: " + e.getMessage(), null);
        }
    }

    private UserResponseDTO mapUserToResponseDTO(UserEntity user) {
        UserResponseDTO responseDTO = new UserResponseDTO();
        responseDTO.setId(user.getId());
        responseDTO.setEmail(user.getEmail());
        responseDTO.setMobileNumber(user.getMobileNumber());
        responseDTO.setIsActive(user.getIsActive());



        logger.debug("Mapping user entity to response DTO. User ID: {}", user.getId());
        return responseDTO;
    }

    private void sendPasswordEmail(String email, String username, String password) {
        String subject = "Your Account Information";
        String emailBody = """
            <html>
            <body>
                <h2>Welcome to Nabil Bank</h2>
                <p>Dear %s,</p>
                <p>Your account has been created successfully. Please find your login details below:</p>
                <p><strong>Username:</strong> %s</p>
                <p><strong>Temporary Password:</strong> %s</p>
                <p>For security reasons, you will be required to change your password when you first log in.</p>
                <p>If you have any questions, please contact our support team.</p>
                <p>Thank you,<br>Nabil Bank Support Team</p>
            </body>
            </html>
            """.formatted(username, username, password);

        emailService.sendEmail(email, subject, emailBody);
        logger.info("[AuthService:sendPasswordEmail] Password email sent");
        logger.debug("[AuthService:sendPasswordEmail] Recipient: {}", maskEmail(email));
    }

    private static Authentication createAuthenticationObject(UserEntity userInfoEntity) {
        // Extract user details
        String username = userInfoEntity.getEmail();


        // Create authorities using role_id
        List<GrantedAuthority> authorities = new ArrayList<>();


        return new UsernamePasswordAuthenticationToken(
                username,
                authorities
        );
    }

    // Helper method to mask emails for safe logging
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        String[] parts = email.split("@");
        return parts[0].charAt(0) + "***@" + parts[1];
    }

    // Helper method to mask DTOs for safe logging
    private String maskUserDto(UserDto userDTO) {
        return "UserDto{id=" + userDTO.getId() + ", email=***}";
    }

    @Override
    @Transactional
    public ApiResponseDto<String> approveUser(UUID id) {
        logger.info("Approving user with ID: {}", id);
        try {
            Optional<UserEntity> userOptional = userRepository.findById(id);
            if (userOptional.isEmpty()) {
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(), "User not found", null);
            }
            UserEntity user = userOptional.get();
            if (user.getAccountStatus() == com.auth.service.entity.AccountStatus.ACTIVE) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(), "User is already active", null);
            }
            if (user.getAccountStatus() == com.auth.service.entity.AccountStatus.UNVERIFIED) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(), "User has not verified OTP yet", null);
            }
            
            user.setAccountStatus(com.auth.service.entity.AccountStatus.ACTIVE);
            user.setIsActive(true);
            userRepository.save(user);
            
            // TODO: Optional - Send email notifying user of approval
            
            return new ApiResponseDto<>(true, HttpStatus.OK.value(), "User approved successfully", null);
        } catch (Exception e) {
            logger.error("Error approving user", e);
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Error approving user", null);
        }
    }

    @Override
    @Transactional
    public ApiResponseDto<String> createInternalUser(InternalUserCreateDto createDto, String creatorEmail) {
        try {
            // Find creator
            Optional<UserEntity> creatorOpt = userRepository.findByEmail(creatorEmail);
            if (creatorOpt.isEmpty()) {
                return new ApiResponseDto<>(false, HttpStatus.UNAUTHORIZED.value(), "Creator not found", null);
            }
            UserEntity creator = creatorOpt.get();
            com.auth.service.entity.Role creatorRole = creator.getRole();
            com.auth.service.entity.Role targetRole = createDto.getRole();

            // Validate hierarchy
            boolean allowed = false;
            if (creatorRole == com.auth.service.entity.Role.SUPER_ADMIN && targetRole == com.auth.service.entity.Role.ADMIN) allowed = true;
            if (creatorRole == com.auth.service.entity.Role.ADMIN && targetRole == com.auth.service.entity.Role.MANAGER) allowed = true;
            if (creatorRole == com.auth.service.entity.Role.MANAGER && (targetRole == com.auth.service.entity.Role.ENGINEER || targetRole == com.auth.service.entity.Role.STAFF)) allowed = true;

            if (!allowed) {
                return new ApiResponseDto<>(false, HttpStatus.FORBIDDEN.value(), "You do not have permission to create this role", null);
            }

            if (userRepository.existsByEmail(createDto.getEmail())) {
                return new ApiResponseDto<>(false, HttpStatus.CONFLICT.value(), "User with this email already exists", null);
            }

            UserEntity newUser = new UserEntity();
            newUser.setName(createDto.getName());
            newUser.setEmail(createDto.getEmail());
            newUser.setMobileNumber(createDto.getMobileNumber());
            newUser.setRole(targetRole);
            newUser.setIsActive(false);
            newUser.setAccountStatus(com.auth.service.entity.AccountStatus.UNVERIFIED);
            
            if (createDto.getHotelId() != null) {
                com.auth.service.entity.HotelEntity proxyHotel = new com.auth.service.entity.HotelEntity();
                proxyHotel.setId(createDto.getHotelId());
                newUser.setHotel(proxyHotel);
            }
            
            // Generate setup token
            String setupToken = UUID.randomUUID().toString();
            newUser.setSetupToken(setupToken);
            // Default password hash (will be changed later)
            newUser.setPasswordHash(passwordEncoder.encode(UUID.randomUUID().toString()));

            userRepository.save(newUser);

            // Send setup email
            String setupLink = mainServiceUrl != null ? mainServiceUrl + "/setup-password?token=" + setupToken : "http://localhost:3000/setup-password?token=" + setupToken;
            String emailBody = "<html><body>" +
                    "<h2>Welcome!</h2>" +
                    "<p>Your account has been created as " + targetRole.name() + ".</p>" +
                    "<p>Please click the link below to set your password and activate your account:</p>" +
                    "<a href=\"" + setupLink + "\">Set Password</a>" +
                    "</body></html>";
                    
            emailService.sendEmail(newUser.getEmail(), "Set Up Your Account", emailBody);

            return new ApiResponseDto<>(true, HttpStatus.CREATED.value(), "User created successfully. Setup email sent.", null);
        } catch (Exception e) {
            logger.error("Error creating internal user", e);
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Error creating internal user", null);
        }
    }
}
