package com.auth.service.service.impl;

import java.util.UUID;

import com.auth.service.config.RSAKeyRecord;
import com.auth.service.config.jwtConfig.JwtTokenGenerator;
import com.auth.service.config.jwtConfig.JwtTokenUtils;
import com.auth.service.dto.*;
import com.auth.service.entity.RefreshTokenEntity;
import com.auth.service.entity.UserEntity;
import java.util.UUID;
import com.auth.service.entity.UserSession;
import com.auth.service.exception.*;
import com.auth.service.exception.LdapException;
import com.auth.service.logger.LoggerAdapter;
import com.auth.service.mapper.UserInfoMapper;
import com.auth.service.repository.RefreshTokenRepo;
import com.auth.service.repository.UserRepo;
import com.auth.service.repository.UserSessionRepository;
import com.auth.service.repository.HotelRepo;
import com.auth.service.entity.HotelEntity;
import com.auth.service.entity.AccountStatus;
import com.auth.service.service.AuthService;
import com.auth.service.service.AuthenticationStrategy;
import com.auth.service.service.EmailService;
import com.auth.service.service.LoginAttemptService;
import com.auth.service.util.FingerprintUtil;
import com.auth.service.util.OtpUtil;
import com.auth.service.util.PasswordGenerator;
import com.auth.service.util.UserUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import javax.security.auth.login.AccountLockedException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final RefreshTokenRepo refreshTokenRepo;
    private final UserInfoMapper userInfoMapper;
    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final LoggerAdapter logger;
    private final OtpUtil otpUtil;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    private final UserSessionRepository userSessionRepository;
    private final HotelRepo hotelRepo;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private FingerprintUtil fingerprintUtil;

    private final UserUtil userUtil;

    @Autowired
    private PasswordGenerator passwordGenerator;

    @Value("${authentication.method}")
    private String authenticationMethod;

    @Value("${otp.method}")
    private String otpMethod;

    @Value("${authentication.password-length:12}")
    private int passwordLength;

    @Value("${spring.mail.username:desnimesh@gmail.com}")
    private String systemEmailSender;

    @Value("${main.service.url:http://localhost:8081}")
    private String mainServiceUrl;

    @Autowired
    private org.springframework.web.client.RestTemplate restTemplate;

    @Autowired
    private DatabaseAuthenticationStrategy databaseAuthenticationStrategy;

    @Autowired
    private LdapAuthenticationStrategy ldapAuthenticationStrategy;

    public ApiResponseDto<Object> authenticateUserWithoutOtp(AuthRequestDto authRequestDto, HttpServletRequest request,
            HttpServletResponse response) {
        String username = authRequestDto.getUsername(); // here iusername is email

        try {
            // Check if the user is blocked
            if (loginAttemptService.isBlocked(username)) {
                throw new AuthenticationException(ErrorCode.ACCOUNT_BLOCKED,
                        "Account is temporarily blocked. Please try again later.");
            }

            // Check if this is a first login for the user
            UserEntity user = userInfoRepo.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // Check user status (assuming 0 is inactive, 1 is active)
            if (user.getIsActive() != null && !user.getIsActive()) {
                throw new AuthenticationException(ErrorCode.ACCOUNT_INACTIVE,
                        "Your account is inactive. Please contact administrator.");
            }

            AuthenticationStrategy strategy = getAuthenticationStrategy();
            Authentication authentication = strategy.authenticate(username, authRequestDto.getPassword());

            if (authentication != null && authentication.isAuthenticated()) {
                loginAttemptService.loginSucceeded(username);

                // Get JWT tokens and authentication data
                Object authResponseObj = getJwtTokensAfterAuthentication(authentication, request, response);

                // Create a proper response with all authentication data
                Map<String, Object> authResponse = new HashMap<>();

                // If authResponseObj is a Map, copy all its entries
                if (authResponseObj instanceof Map) {
                    authResponse.putAll((Map<String, Object>) authResponseObj);
                } else {
                    // Handle the case where authResponseObj is not a Map
                    // This depends on what getJwtTokensAfterAuthentication actually returns
                    authResponse.put("authData", authResponseObj);
                }
                // Regular login response
                authResponse.put("requiresPasswordReset", false);

                return new ApiResponseDto<>(true, 1000,
                        "Authentication successful", authResponse);

            } else {
                throw new BadCredentialsException("Invalid username or password");
            }
        } catch (AuthenticationException e) {
            logger.error("Authentication error: {}", e.getMessage());
            return new ApiResponseDto<>(false, e.getErrorCode().getCode(),
                    e.getMessage(), null);
        } catch (BadCredentialsException e) {
            logger.error("Bad credentials: {}", e.getMessage());
            loginAttemptService.loginFailed(username);
            return new ApiResponseDto<>(false, ErrorCode.INVALID_CREDENTIALS.getCode(),
                    "Invalid username or password", null);
        } catch (LdapException e) {
            logger.error("LDAP error: {}", e.getMessage());
            int errorCode = e.getErrorCode().getCode();
            String errorMessage = e.getMessage();

            if (errorCode == ErrorCode.LDAP_CONNECTION_FAILED.getCode()) {
                return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        "Unable to connect to LDAP server", null);
            } else if (errorCode == ErrorCode.LDAP_AUTHENTICATION_FAILED.getCode()) {
                loginAttemptService.loginFailed(username);
                return new ApiResponseDto<>(false, ErrorCode.LDAP_AUTHENTICATION_FAILED.getCode(),
                        "Authentication failed: " + errorMessage, null);
            }

            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Unexpected error during authentication", null);
        } catch (Exception e) {
            logger.error("Unexpected error during authentication", e);
            return new ApiResponseDto<>(false, ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    "An unexpected error occurred. Please try again later.", null);
        }
    }

    public ApiResponseDto<Object> authenticateUser(AuthRequestDto authRequestDto, HttpServletResponse response) {
        String username = authRequestDto.getUsername();
        String password = authRequestDto.getPassword();

        try {
            UserEntity user = userInfoRepo.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // Check account status
            // if (user!.getIsActive()) { // 1 = active/enabled
            // throw new DisabledException("Account is not active");
            // }

            // Check if account is blocked
            if (loginAttemptService.isBlocked(username)) {
                throw new AccountLockedException("Account is temporarily locked");
            }

            // Password validation logic
            if (user.getPasswordHash() != null) {
                if (password == null || password.isBlank()) {
                    throw new CustomAuthenticationException(ErrorCode.PASSWORD_REQUIRED,
                            "Password required for this account");
                }

                // Authenticate using password
                AuthenticationStrategy strategy = getAuthenticationStrategy();
                Authentication authentication = strategy.authenticate(username, password);

                if (authentication == null || !authentication.isAuthenticated()) {
                    throw new BadCredentialsException("Invalid username or password");
                }
            } else {
                if (password != null && !password.isBlank()) {
                    throw new CustomAuthenticationException(ErrorCode.PASSWORD_NOT_SET,
                            "Password not set for this account");
                }
            }

            loginAttemptService.loginSucceeded(username);

            // Generate and send OTP
            String otp = otpUtil.generateOtp();
            user.setOtp(otp);
            user.setOtpExpiry(otpUtil.generateOtpExpiry());
            userInfoRepo.save(user);
            emailService.sendOtpEmail(user.getEmail(), otp);

            // Return empty data object instead of null for consistency with client expectations
            Map<String, Object> emptyData = new java.util.HashMap<>();
            return new ApiResponseDto<>(true, 2001,
                    "OTP sent to registered email. Please verify OTP to complete login.", emptyData);

        } catch (BadCredentialsException e) {
            logger.error("Bad credentials: {}", e.getMessage());
            loginAttemptService.loginFailed(username);
            return new ApiResponseDto<>(false, ErrorCode.INVALID_CREDENTIALS.getCode(),
                    e.getMessage(), null, new ApiResponseDto.ErrorDetails2(ErrorCode.INVALID_CREDENTIALS.getCode()));

        } catch (UsernameNotFoundException e) {
            logger.error("User not found: {}", e.getMessage());
            loginAttemptService.loginFailed(username);
            return new ApiResponseDto<>(false, ErrorCode.USER_NOT_FOUND.getCode(),
                    e.getMessage(), null, new ApiResponseDto.ErrorDetails2(ErrorCode.USER_NOT_FOUND.getCode()));

        } catch (DisabledException e) {
            logger.error("Account inactive: {}", e.getMessage());
            return new ApiResponseDto<>(false, ErrorCode.ACCOUNT_INACTIVE.getCode(),
                    e.getMessage(), null, new ApiResponseDto.ErrorDetails2(ErrorCode.ACCOUNT_INACTIVE.getCode()));

        } catch (AccountLockedException e) {
            logger.error("Account locked: {}", e.getMessage());
            return new ApiResponseDto<>(false, ErrorCode.ACCOUNT_LOCKED.getCode(),
                    e.getMessage(), null, new ApiResponseDto.ErrorDetails2(ErrorCode.ACCOUNT_LOCKED.getCode()));

        } catch (CustomAuthenticationException e) {
            logger.error("Authentication policy violation: {}", e.getMessage());
            loginAttemptService.loginFailed(username);
            return new ApiResponseDto<>(false, e.getErrorCode().getCode(),
                    e.getMessage(), null, new ApiResponseDto.ErrorDetails2(e.getErrorCode().getCode()));

        } catch (EmailException e) {
            logger.error("Email error: {}", e.getMessage());
            return handleEmailException(e);

        } catch (Exception e) {
            logger.error("Unexpected error: {}", e.getMessage());
            return new ApiResponseDto<>(false, ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    "An unexpected error occurred", null,
                    new ApiResponseDto.ErrorDetails2(ErrorCode.INTERNAL_SERVER_ERROR.getCode()));
        }
    }

    public ApiResponseDto<Object> registerWithPassword(PasswordRegistrationDto dto, HttpServletRequest request) {
        try {
            logger.info("[AuthService:registerWithPassword] Password registration: {}", dto.userEmail());

            // Check existing users
            if (userInfoRepo.findByEmail(dto.userEmail()).isPresent()) {
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.EMAIL_ALREADY_EXISTS.getCode(),
                        "Email already registered",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.EMAIL_ALREADY_EXISTS.getCode()));
            }
            if (userInfoRepo.findByMobileNumber(dto.userMobileNo()).isPresent()) {
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.MOBILE_ALREADY_EXISTS.getCode(),
                        "Mobile number already registered",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.MOBILE_ALREADY_EXISTS.getCode()));
            }

            // Create user entity
            UserEntity userEntity = new UserEntity();
            userEntity.setPasswordHash(passwordEncoder.encode(dto.password()));
            userEntity.setEmail(dto.userEmail());
            userEntity.setRole(com.auth.service.entity.Role.TECHNICIAN);
            userEntity.setIsActive(true); // Active immediately
            userEntity.setOtp(null); // No OTP needed
            userEntity.setOtpExpiry(null);

            UserEntity savedUser = userInfoRepo.save(userEntity);
            logger.info("[AuthService:registerWithPassword] User registered: {}", savedUser.getEmail());

            return generateAuthResponse(savedUser, request);

        } catch (Exception e) {
            logger.error("[AuthService:registerWithPassword] Error: {}", e.getMessage(), e);
            return new ApiResponseDto<>(
                    false,
                    ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    "Registration failed",
                    null,
                    new ApiResponseDto.ErrorDetails2(ErrorCode.INTERNAL_SERVER_ERROR.getCode()));
        }
    }

    public ApiResponseDto<Object> authenticateWithPassword(
            String usernameOrEmail,
            String password,
            HttpServletRequest request) {

        try {
            logger.info("[AuthService:authenticateWithPassword] Attempt: {}", usernameOrEmail);

            // Find user by email
            Optional<UserEntity> userOptional = userInfoRepo.findByEmail(usernameOrEmail);
            if (userOptional.isEmpty()) {
                logger.warn("[AuthService:authenticateWithPassword] User not found: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.USER_NOT_FOUND.getCode(),
                        "Invalid credentials",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.USER_NOT_FOUND.getCode()));
            }

            UserEntity user = userOptional.get();

            // Check LDAP restriction
            if ("ldap".equalsIgnoreCase(authenticationMethod)) {
                logger.warn("[AuthService:authenticateWithPassword] LDAP restriction for: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.LDAP_RESTRICTION.getCode(),
                        "Password login not available for LDAP users",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.LDAP_RESTRICTION.getCode()));
            }

            // Verify password
            if (!passwordEncoder.matches(password, user.getPasswordHash())) {
                logger.warn("[AuthService:authenticateWithPassword] Invalid password for: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.INVALID_CREDENTIALS.getCode(),
                        "Invalid credentials",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.INVALID_CREDENTIALS.getCode()));
            }

            // Check account status
            if (!user.getIsActive()) {
                logger.warn("[AuthService:authenticateWithPassword] Inactive account: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.ACCOUNT_INACTIVE.getCode(),
                        "Account not verified",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.ACCOUNT_INACTIVE.getCode()));
            }

            return generateAuthResponse(user, request);

        } catch (Exception e) {
            logger.error("[AuthService:authenticateWithPassword] Error: {}", e.getMessage(), e);
            return new ApiResponseDto<>(
                    false,
                    ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    "Authentication failed",
                    null,
                    new ApiResponseDto.ErrorDetails2(ErrorCode.INTERNAL_SERVER_ERROR.getCode()));
        }
    }

        private ApiResponseDto<Object> generateAuthResponse(UserEntity user, HttpServletRequest request) {
        List<GrantedAuthority> authorities = getAuthorities(user);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
            user.getEmail(),
            null,
            authorities);

        // Generate fingerprint and session
        String fingerprintHash = fingerprintUtil.generateFingerprint(request, user.getEmail());
        String sessionId = java.util.UUID.randomUUID().toString();

        UserSession session = new UserSession();
        session.setSessionId(sessionId);
        session.setUserId(user.getId());
        session.setStatus("ACTIVE");
        try {
            session.setIpAddress(request.getRemoteAddr());
        } catch (Exception ignored) {
        }
        userSessionRepository.save(session);

        String accessToken = jwtTokenGenerator.generateAccessToken(
            authentication,
            user.getId(),
            user.getEmail(),
            fingerprintHash,
            sessionId);
        String refreshToken = jwtTokenGenerator.generateRefreshToken(
            authentication,
            user.getId(),
            fingerprintHash,
            sessionId);

        // Save refresh token
        saveUserRefreshToken(user, refreshToken);

        // Build response
        Map<String, Object> authData = new HashMap<>();
        authData.put("access_token", accessToken);
        authData.put("refreshToken", refreshToken);
        authData.put("fingerprint", fingerprintHash);
        authData.put("user_name", user.getEmail());
        authData.put("user_id", user.getId()); // Add user ID for mobile app
        authData.put("access_token_expiry", 86400); // 1 day in seconds, matches JWT expiry
        authData.put("token_type", "Bearer");
        authData.put("hasPinSet", user.getPinHash() != null && !user.getPinHash().isEmpty());

        Map<String, Object> data = new HashMap<>();
        data.put("authData", authData);

        return new ApiResponseDto<>(
                true,
                HttpStatus.OK.value(),
                "Authentication successful",
                data);
    }

    // Helper method for email exceptions
    private ApiResponseDto<Object> handleEmailException(EmailException e) {
        if (e.getErrorCode() == ErrorCode.EMAIL_INVALID_ADDRESS) {
            return new ApiResponseDto<>(false, e.getErrorCode().getCode(),
                    "Invalid email address. Please update your email and try again.", null,
                    new ApiResponseDto.ErrorDetails2(e.getErrorCode().getCode()));
        } else {
            return new ApiResponseDto<>(false, e.getErrorCode().getCode(),
                    "Failed to send OTP. Please try again.", null,
                    new ApiResponseDto.ErrorDetails2(e.getErrorCode().getCode()));
        }
    }

    private AuthenticationStrategy getAuthenticationStrategy() {
        if ("ldap".equalsIgnoreCase(authenticationMethod)) {
            return ldapAuthenticationStrategy;
        }
        return databaseAuthenticationStrategy;
    }

    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            String username = authentication.getName();

            // 1. Check if user is blocked (redundant safety check)
            if (loginAttemptService.isBlocked(username)) {
                logger.error("[AuthService] User {} blocked", username);
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account blocked");
            }

            // 2. Fetch user details
            UserEntity user = userInfoRepo.findByEmail(username)
                    .orElseThrow(() -> {
                        logger.error("[AuthService] User {} not found", username);
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
                    });

                // 3. Generate fingerprint
                String fingerprintHash = fingerprintUtil.generateFingerprint(request, username);
                logger.debug("Generated fingerprint for {}", username);

                // 4. Create a session and generate tokens
                String sessionId = java.util.UUID.randomUUID().toString();

                UserSession session = new UserSession();
                session.setSessionId(sessionId);
                session.setUserId(user.getId());
                session.setStatus("ACTIVE");
                try {
                session.setIpAddress(request.getRemoteAddr());
                } catch (Exception ignored) {
                }
                userSessionRepository.save(session);

                String accessToken = jwtTokenGenerator.generateAccessToken(
                    authentication,
                    user.getId(),
                    user.getEmail(),
                    fingerprintHash,
                    sessionId);

                String refreshToken = jwtTokenGenerator.generateRefreshToken(
                    authentication,
                    user.getId(),
                    fingerprintHash,
                    sessionId);

            // 5. Save refresh token and set cookie
            saveUserRefreshToken(user, refreshToken);
            createRefreshTokenCookie(response, refreshToken);

            logger.info("[AuthService] Tokens generated for {}", username);

            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .accessTokenExpiry(5 * 60) // 5 minutes
                    .fingerprint(fingerprintHash)
                    .userName(user.getEmail())
                    .build();

        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("[AuthService] Token generation error: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Token generation failed");
        }
    }

    private void createRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true); // Use false for local development
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60); // 15 days

        // Add SameSite attribute
        String cookieHeader = String.format(
                "%s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Lax; %s",
                refreshTokenCookie.getName(),
                refreshTokenCookie.getValue(),
                refreshTokenCookie.getPath(),
                refreshTokenCookie.getMaxAge(),
                refreshTokenCookie.getSecure() ? "Secure" : "");

        response.addHeader("Set-Cookie", cookieHeader);
        logger.info("[AuthService] Refresh token cookie set");
    }

    private void saveUserRefreshToken(UserEntity userInfoEntity, String refreshToken) {
        var refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userInfoEntity)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    public Object getAccessTokenUsingRefreshToken(HttpServletRequest request, String authorizationHeader) { // when
                                                                                                            // access
                                                                                                            // token get
                                                                                                            // expair,
                                                                                                            // can get
                                                                                                            // the again
                                                                                                            // acceses
                                                                                                            // token
                                                                                                            // using
                                                                                                            // refresh
                                                                                                            // token

        if (!authorizationHeader.startsWith(TokenType.Bearer.name())) {
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please verify your token type");
        }

        final String refreshToken = authorizationHeader.substring(7).trim().toUpperCase();
        logger.info("[AuthService:getAccessTokenUsingRefreshToken] Searching for token. Length: {}, Start: {}", 
            refreshToken.length(),
            refreshToken.substring(0, Math.min(refreshToken.length(), 10)));

        var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token not found in database"));

        if (refreshTokenEntity.isRevoked()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token has been revoked");
        }

        UserEntity userInfoEntity = refreshTokenEntity.getUser();

        // Now create the Authentication object
        Authentication authentication = createAuthenticationObject(userInfoEntity);
        String username = authentication.getName();
        String fingerprintHash = fingerprintUtil.generateFingerprint(request, username);
        logger.debug("Fingerprint generated for user");

        // Use the authentication object to generate new accessToken.
        // Preserve the original sessionId from the refresh token so that
        // access token refresh does not create a new session.
        String sessionId = extractSessionIdFromRefreshToken(refreshToken);

        String accessToken = jwtTokenGenerator.generateAccessToken(authentication, userInfoEntity.getId(),
            userInfoEntity.getEmail(), fingerprintHash, sessionId);
        logger.info("AccessToken ", accessToken);

        // String roles = getRolesOfUser(authentication);

        System.out.println("accessToken " + accessToken);
        return AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .tokenType(TokenType.Bearer)
                .fingerprint(fingerprintHash)
                // .isFirstLogin(userInfoEntity.isFirstLogin())
                .build();
    }

    /**
     * Decode the (possibly ciphered) refresh token and extract the sessionId claim.
     * If anything goes wrong, a new sessionId is generated as a safe fallback.
     */
    private String extractSessionIdFromRefreshToken(String refreshToken) {
        try {
            // refreshToken stored in DB and received from client is the ciphered token.
            // We need the underlying JWT token value. TokenCipher returns the plain JWT
            // from the HEX-encoded cipher.
            com.auth.service.util.TokenCipher tokenCipher = new com.auth.service.util.TokenCipher();

            // Load keyset from embedded JSON (same as JwtTokenGenerator)
            String keyJson = "{" +
                    "\"primaryKeyId\":339737423," +
                    "\"key\":[" +
                    "  {" +
                    "    \"keyData\":{" +
                    "      \"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\"," +
                    "      \"value\":\"GiCdyK5Sr8dC9PfXKRxfyYWR9sl5DgejhdsojzoYJ76PGA==\"," +
                    "      \"keyMaterialType\":\"SYMMETRIC\"" +
                    "    }," +
                    "    \"status\":\"ENABLED\"," +
                    "    \"keyId\":339737423," +
                    "    \"outputPrefixType\":\"TINK\"" +
                    "  }" +
                    "]" +
                    "}";

            com.google.crypto.tink.KeysetHandle keysetHandle =
                    com.google.crypto.tink.CleartextKeysetHandle.read(
                            com.google.crypto.tink.JsonKeysetReader.withString(keyJson));

            String plainJwt = tokenCipher.decipherToken(refreshToken, keysetHandle);

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            Jwt jwtToken = jwtDecoder.decode(plainJwt);

            String sessionId = jwtToken.getClaim("sessionId");
            if (sessionId == null || sessionId.isEmpty()) {
                return java.util.UUID.randomUUID().toString();
            }
            return sessionId;
        } catch (Exception e) {
            logger.error("[AuthService] Failed to extract sessionId from refresh token: {}", e.getMessage());
            return java.util.UUID.randomUUID().toString();
        }
    }

    private static Authentication createAuthenticationObject(UserEntity userInfoEntity) {
        // Extract user details
        String username = userInfoEntity.getEmail();

        // Create authorities using role_id
        List<GrantedAuthority> authorities = new ArrayList<>();

        // Add role_id based authority
        return new UsernamePasswordAuthenticationToken(
                username,
                authorities);
    }

    @Override
    @Transactional
    public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto,
            HttpServletRequest request,
            HttpServletResponse httpServletResponse) {
        try {
            logger.info("[AuthService:registerUser] User Registration Started ::: {}", userRegistrationDto);


            // Check if email already exists
            if (userInfoRepo.existsByEmailAndIsActive(userRegistrationDto.userEmail(), true)) {
                logger.warn("[AuthService:registerUser] Email already registered: {}", userRegistrationDto.userEmail());
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
            }
            
            // Check if mobile number already exists
            if (userInfoRepo.existsByMobileNumberAndIsActive(userRegistrationDto.userMobileNo(), true)) {
                logger.warn("[AuthService:registerUser] Mobile number already registered: {}", userRegistrationDto.userMobileNo());
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Mobile number already registered");
            }
            
            
            // Create user entity without password
            UserEntity userEntity = userInfoMapper.convertToEntity(userRegistrationDto);
            
            if (userRegistrationDto.hotelId() != null) {
                HotelEntity hotel = hotelRepo.findById(userRegistrationDto.hotelId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid hotel ID"));
                userEntity.setHotel(hotel);
            }
            
            userEntity.setPasswordHash(passwordEncoder.encode(userRegistrationDto.userPassword()));
            userEntity.setAccountStatus(AccountStatus.UNVERIFIED);
            userEntity.setIsActive(false); // Can keep this for backwards compatibility
            
            logger.debug("[AuthService:registerUser] User entity created.");

            // Generate and store OTP
            String otp = otpUtil.generateOtp();
            userEntity.setOtp(otp);
            userEntity.setOtpExpiry(otpUtil.generateOtpExpiry());
            UserEntity savedUser = userInfoRepo.save(userEntity);
            
            logger.debug("[AuthService:registerUser] User saved successfully.");

            // Send OTP via email
            emailService.sendOtpEmail(savedUser.getEmail(), otp);

            logger.info("[AuthService:registerUser] OTP sent to user: {}", savedUser.getEmail());

            // Return response without tokens
            return AuthResponseDto.builder()
                    .message("OTP sent to email. Verify to complete registration.")
                    .build();
        } catch (ResponseStatusException e) {
            logger.error("[AuthService:registerUser] Registration error: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("[AuthService:registerUser] Unexpected error: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", e);
        }
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
        logger.info("[AuthService:sendPasswordEmail] Password email sent to: {}", email);
    }

    public String GetUserRole(String token) {
        try {
            logger.info("Received token: {}", token);
            final String token2 = token.substring(7);
            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final Jwt jwtToken = jwtDecoder.decode(token2); // decode the JWT token
            final String role = jwtTokenUtils.getRole(jwtToken);
            return role;
        } catch (Exception e) {
            logger.error(
                    "[AuthService:userSignInAuth]Exception while authenticating the user due to :" + e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }

    public ApiResponseDto<Object> verifyOtp(OtpVerificationDto otpVerificationDto,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            String username = otpVerificationDto.usernameOrEmail();

            // 1. Check if account is blocked
            if (loginAttemptService.isBlocked(username)) {
                throw new AuthenticationException(ErrorCode.ACCOUNT_BLOCKED,
                        "Account is temporarily blocked. Please try again later.");
            }

            // 2. Verify OTP
            Optional<UserEntity> userEntityOptional = userInfoRepo.findByEmailAndOtp(
                    username, otpVerificationDto.otp());

            if (userEntityOptional.isEmpty()) {
                loginAttemptService.loginFailed(username); // Record failed attempt
                return new ApiResponseDto<>(false, ErrorCode.INVALID_OTP.getCode(),
                        "Invalid OTP", null);
            }

            UserEntity user = userEntityOptional.get();
            if (user.getOtpExpiry() == null || user.getOtpExpiry().isBefore(LocalDateTime.now())) {
                loginAttemptService.loginFailed(username); // Record failed attempt
                return new ApiResponseDto<>(false, ErrorCode.OTP_EXPIRED.getCode(),
                        "OTP expired", null);
            }

            // 3. Clear OTP after successful verification
            // 3. Update account status to PENDING_APPROVAL
            user.setOtp(null);
            user.setOtpExpiry(null);
            user.setAccountStatus(AccountStatus.PENDING_APPROVAL);
            UserEntity savedUser = userInfoRepo.save(user);

            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "OTP verified successfully. Your account is pending admin approval.", null);

        } catch (AuthenticationException e) {
            logger.error("Authentication error: {}", e.getMessage());
            return new ApiResponseDto<>(false, e.getErrorCode().getCode(),
                    e.getMessage(), null, new ApiResponseDto.ErrorDetails2(e.getErrorCode().getCode()));
        } catch (Exception e) {
            logger.error("Unexpected error during OTP verification", e);
            return new ApiResponseDto<>(false, ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    "An unexpected error occurred", null,
                    new ApiResponseDto.ErrorDetails2(ErrorCode.INTERNAL_SERVER_ERROR.getCode()));
        }
    }

    // Helper method to get authorities
    private List<GrantedAuthority> getAuthorities(UserEntity user) {
        String roleStr = user.getRole() != null ? user.getRole().name() : "TECHNICIAN";
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + roleStr));
    }

    private Authentication createAuthenticationFromUser(UserEntity userEntity) {
        List<GrantedAuthority> authorities = getAuthorities(userEntity);

        return new UsernamePasswordAuthenticationToken(
                userEntity.getEmail(),
                null,
                authorities);
    }

    public ApiResponseDto<String> reSendOtp(String usernameOrEmail) {
        try {
            // First try to find by username
            Optional<UserEntity> userOptional = userInfoRepo.findByEmail(usernameOrEmail);

            // If not found by username, try by email
            if (userOptional.isEmpty()) {
                userOptional = userInfoRepo.findByEmail(usernameOrEmail);
            }

            if (userOptional.isEmpty()) {
                logger.warn("OTP resend attempt for non-existent user: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.NOT_FOUND.value(),
                        "No account found with this username or email.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1004));
            }

            UserEntity user = userOptional.get();
            sendOtpOrEmailVerification(user);

            logger.info("OTP resent successfully for user: {}", usernameOrEmail);
            return new ApiResponseDto<>(
                    true,
                    HttpStatus.OK.value(),
                    "OTP has been resent successfully",
                    null,
                    null);

        } catch (Exception e) {
            logger.error("Error while resending OTP for user: {}", usernameOrEmail, e);
            return new ApiResponseDto<>(
                    false,
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Failed to resend OTP. Please try again later.",
                    null,
                    new ApiResponseDto.ErrorDetails2(5001));
        }
    }

    public void sendOtpOrEmailVerification(UserEntity user) {

        String otp = otpUtil.generateOtp();
        LocalDateTime otpExpiry = OtpUtil.generateOtpExpiry();
        user.setOtp(otp);
        user.setOtpExpiry(otpExpiry);
        userInfoRepo.save(user);

        if ("sms".equalsIgnoreCase(otpMethod)) {
            String formattedPhoneNumber = formatPhoneNumber(user.getMobileNumber());
            otpUtil.sendOtpSms(formattedPhoneNumber, otp);
            logger.info("OTP sent via SMS to {}", formattedPhoneNumber);
        } else if ("email".equalsIgnoreCase(otpMethod)) {
            emailService.sendOtpEmail(user.getEmail(), otp);
            logger.info("OTP sent via email to {}", user.getEmail());
        } else {
            throw new IllegalStateException("Invalid OTP method configured");
        }
    }

    private String formatPhoneNumber(String mobileNumber) {
        if (mobileNumber.startsWith("0")) {
            return "+94" + mobileNumber.substring(1);
        }
        return mobileNumber;
    }

    @Override
    public ApiResponseDto<String> firstLoginResetPassword(FirstLoginPasswordResetDto resetDto) {
        try {
            UUID userId = userUtil.getId();
            logger.info("[AuthService:firstLoginResetPassword] First login password reset requested for user ID: {}",
                    userId);

            // Validate passwords match
            if (!resetDto.newPassword().equals(resetDto.confirmPassword())) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                        "New password and confirm password do not match", null);
            }

            // Find user by user ID
            Optional<UserEntity> userOptional = userInfoRepo.findById(userId);
            if (userOptional.isEmpty()) {
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(),
                        "User not found with user ID: " + userId, null);
            }

            UserEntity user = userOptional.get();

            // Check if LDAP authentication is enabled
            boolean isLdapAuth = "ldap".equalsIgnoreCase(authenticationMethod);
            if (isLdapAuth) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(),
                        "Password reset is not available for LDAP users. Please contact your system administrator.",
                        null);
            }

            // Update password and f
            user.setIsActive(true);

            userInfoRepo.save(user);

            logger.info("[AuthService:firstLoginResetPassword] First login password reset successful for user: {}",
                    user.getEmail());
            return new ApiResponseDto<>(true, HttpStatus.OK.value(),
                    "Password set successfully", null);

        } catch (Exception e) {
            logger.error("[AuthService:firstLoginResetPassword] Error in first login password reset: {}",
                    e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while setting the password: " + e.getMessage(), null);
        }
    }

    @Override
    public ApiResponseDto<String> initiatePasswordReset(String usernameOrEmail) {
        try {
            logger.info("[AuthService:initiatePasswordReset] Password reset requested for: {}", usernameOrEmail);

            // First try to find by username
            Optional<UserEntity> userOptional = userInfoRepo.findByEmail(usernameOrEmail);

            // If not found by username, try by email
            if (userOptional.isEmpty()) {
                userOptional = userInfoRepo.findByEmail(usernameOrEmail);
            }

            if (userOptional.isEmpty()) {
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.NOT_FOUND.value(),
                        "No account found with this username or email.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1004));
            }

            UserEntity user = userOptional.get();

            // Check if LDAP authentication is enabled for this user
            boolean isLdapAuth = "ldap".equalsIgnoreCase(authenticationMethod);
            if (isLdapAuth) {
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.BAD_REQUEST.value(),
                        "Password reset is not available for LDAP users. Please contact your system administrator.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1008));
            }

            sendOtpOrEmailVerification(user);
            logger.info("[AuthService:initiatePasswordReset] Password reset OTP sent to: {}", user.getEmail());

            return new ApiResponseDto<>(
                    true,
                    HttpStatus.OK.value(),
                    "Password reset OTP sent to your email address.",
                    null);
        } catch (Exception e) {
            logger.error("[AuthService:initiatePasswordReset] Error initiating password reset: {}", e.getMessage());
            return new ApiResponseDto<>(
                    false,
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while initiating password reset: " + e.getMessage(),
                    null,
                    new ApiResponseDto.ErrorDetails2(1009));
        }
    }

    @Override
    public ApiResponseDto<String> verifyOtp(String usernameOrEmail, String otp) {
        try {
            logger.info("[AuthService:verifyOtp] OTP verification requested for: {}", usernameOrEmail);

            // First try to find by username
            Optional<UserEntity> userOptional = userInfoRepo.findByEmail(usernameOrEmail);

            // If not found by username, try by email
            if (userOptional.isEmpty()) {
                userOptional = userInfoRepo.findByEmail(usernameOrEmail);
            }

            if (userOptional.isEmpty()) {
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.NOT_FOUND.value(),
                        "No account found with this username or email.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1004));
            }

            UserEntity user = userOptional.get();

            // Check if LDAP authentication is enabled for this user
            boolean isLdapAuth = "ldap".equalsIgnoreCase(authenticationMethod);
            if (isLdapAuth) {
                logger.info("[AuthService:verifyOtp] Password reset not available for LDAP user: {}",
                        user.getEmail());
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.BAD_REQUEST.value(),
                        "Password reset is not available for LDAP users. Please contact your system administrator.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1008));
            }
            // Check if OTP exists and is valid
            if (user.getOtp() == null || !user.getOtp().equals(otp)) {
                logger.warn("[AuthService:verifyOtp] Invalid OTP provided for user: {}", user.getEmail());
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.BAD_REQUEST.value(),
                        "Invalid OTP.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1006));
            }

            // Check if OTP is expired
            if (user.getOtpExpiry() == null || user.getOtpExpiry().isBefore(LocalDateTime.now())) {
                logger.warn("[AuthService:verifyOtp] Expired OTP provided for user: {}", user.getEmail());
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.BAD_REQUEST.value(),
                        "OTP has expired. Please request a new one.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1007));
            }

            logger.info("[AuthService:verifyOtp] OTP verified successfully for user: {}", user.getEmail());
            return new ApiResponseDto<>(
                    true,
                    HttpStatus.OK.value(),
                    "OTP verified successfully.",
                    null);
        } catch (Exception e) {
            logger.error("[AuthService:verifyOtp] Error verifying OTP: {}", e.getMessage());
            return new ApiResponseDto<>(
                    false,
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while verifying OTP: " + e.getMessage(),
                    null,
                    new ApiResponseDto.ErrorDetails2(1010));
        }
    }

    public ApiResponseDto<Object> verifyOtpForAuthentication(
            String usernameOrEmail,
            String otp,
            HttpServletRequest request,
            HttpServletResponse response) {

        try {
            logger.info("[AuthService] OTP authentication for: {}", usernameOrEmail);

            // Find user by email
            Optional<UserEntity> userOptional = userInfoRepo.findByEmail(usernameOrEmail);
            if (userOptional.isEmpty()) {
                logger.warn("[AuthService] User not found: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.USER_NOT_FOUND.getCode(),
                        "User not found",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.USER_NOT_FOUND.getCode()));
            }

            UserEntity user = userOptional.get();

            // OTP validation
            if (user.getOtp() == null || !user.getOtp().equals(otp)) {
                logger.warn("[AuthService] Invalid OTP for user: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.INVALID_OTP.getCode(),
                        "Invalid OTP",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.INVALID_OTP.getCode()));
            }

            if (user.getOtpExpiry().isBefore(LocalDateTime.now())) {
                logger.warn("[AuthService] Expired OTP for user: {}", usernameOrEmail);
                return new ApiResponseDto<>(
                        false,
                        ErrorCode.OTP_EXPIRED.getCode(),
                        "OTP expired",
                        null,
                        new ApiResponseDto.ErrorDetails2(ErrorCode.OTP_EXPIRED.getCode()));
            }

            // Clear OTP
            user.setOtp(null);
            user.setIsActive(true); // Activate user
            user.setOtpExpiry(null);
            UserEntity savedUser = userInfoRepo.save(user);
            logger.info("[AuthService] OTP cleared for user: {}", usernameOrEmail);
// SYNC USER TO MAIN SERVICE
            logger.info("[AuthService] Starting sync to Main Service for userId: {}", savedUser.getId());
            boolean syncSuccess = syncUserToMainService(savedUser);
            if (syncSuccess) {
                logger.info("[AuthService] User synced to Main Service successfully.");
            } else {
                logger.warn("[AuthService] User sync to Main Service failed for userId={}.", savedUser.getId());
            }

                List<GrantedAuthority> authorities = getAuthorities(user);

                Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user.getEmail(),
                    null,
                    authorities);

                // Generate fingerprint and create a new session
                String fingerprintHash = fingerprintUtil.generateFingerprint(request, user.getEmail());
                String sessionId = java.util.UUID.randomUUID().toString();

                UserSession session = new UserSession();
                session.setSessionId(sessionId);
                session.setUserId(user.getId());
                session.setStatus("ACTIVE");
                try {
                session.setIpAddress(request.getRemoteAddr());
                } catch (Exception ignored) {
                }
                userSessionRepository.save(session);

                String accessToken = jwtTokenGenerator.generateAccessToken(
                    authentication,
                    user.getId(),
                    user.getEmail(),
                    fingerprintHash,
                    sessionId);
                String refreshToken = jwtTokenGenerator.generateRefreshToken(
                    authentication,
                    user.getId(),
                    fingerprintHash,
                    sessionId);

            // Save refresh token
            saveUserRefreshToken(user, refreshToken);

            // Set authentication cookies
            setAuthCookies(response, accessToken, refreshToken, fingerprintHash);
            logger.info("[AuthService] Auth cookies set for user: {}", usernameOrEmail);

            // Create response structure that matches BFF expectations
            Map<String, Object> authData = new HashMap<>();
            authData.put("access_token", accessToken);
            authData.put("refreshToken", refreshToken);
            authData.put("fingerprint", fingerprintHash);
            authData.put("user_name", user.getEmail());
            authData.put("user_id", user.getId()); // Add user ID for mobile app
            authData.put("user_mobile", user.getMobileNumber());
            authData.put("access_token_expiry", 86400); // 1 day in seconds, matches JWT expiry
            authData.put("token_type", "Bearer");
            authData.put("userSyncedToMainService", syncSuccess); // Let client know if sync succeeded
            authData.put("hasPinSet", user.getPinHash() != null && !user.getPinHash().isEmpty());

            Map<String, Object> data = new HashMap<>();
            data.put("authData", authData);

            return new ApiResponseDto<>(
                    true,
                    HttpStatus.OK.value(),
                    "Authentication successful",
                    data);

        } catch (Exception e) {
            logger.error("[AuthService] OTP authentication failed: {}", e.getMessage(), e);
            return new ApiResponseDto<>(
                    false,
                    ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    "Authentication failed",
                    null,
                    new ApiResponseDto.ErrorDetails2(ErrorCode.INTERNAL_SERVER_ERROR.getCode()));
        }
    }

    private AuthResponseDto generateTokensAndCookies(Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {

        String username = authentication.getName();
        logger.debug("[AuthService] Generating tokens for: {}", username);

        // Fetch user details
        UserEntity user = userInfoRepo.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // Generate fingerprint
        String fingerprintHash = fingerprintUtil.generateFingerprint(request, username);
        logger.debug("[AuthService] Generated fingerprint: {}", fingerprintHash);

        // Create a session and generate tokens
        String sessionId = java.util.UUID.randomUUID().toString();

        UserSession session = new UserSession();
        session.setSessionId(sessionId);
        session.setUserId(user.getId());
        session.setStatus("ACTIVE");
        try {
            session.setIpAddress(request.getRemoteAddr());
        } catch (Exception ignored) {
        }
        userSessionRepository.save(session);

        String accessToken = jwtTokenGenerator.generateAccessToken(
            authentication,
            user.getId(),
            user.getEmail(),
            fingerprintHash,
            sessionId);

        String refreshToken = jwtTokenGenerator.generateRefreshToken(
            authentication,
            user.getId(),
            fingerprintHash,
            sessionId);

        // Save refresh token
        saveUserRefreshToken(user, refreshToken);
        logger.debug("[AuthService] Refresh token saved for user: {}", username);

        // Set all three cookies
        setAuthCookies(response, accessToken, refreshToken, fingerprintHash);

        // Return token information (optional - can be removed if not needed)
        return AuthResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpiry(5 * 60) // 5 minutes
                .fingerprint(fingerprintHash)
                .userName(user.getEmail())
                .build();
    }

    private void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        try {
            ResponseCookie cookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(false) // Set to true in production
                    .path("/")
                    .maxAge(Duration.ofDays(15))
                    .sameSite("Lax") // Use "None" for cross-site if needed
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
            logger.debug("[AuthService] Cookie value: {}", cookie.toString());

        } catch (Exception e) {
            logger.error("[AuthService] Failed to set cookie: {}", e.getMessage());
            // Add error to response header for debugging
            response.addHeader("X-Cookie-Error", e.getMessage());
        }
    }

    private void setAuthCookies(HttpServletResponse response,
            String accessToken,
            String refreshToken,
            String fingerprint) {
        try {
            // 1. Refresh Token Cookie
            ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(false) // Set to true in production
                    .path("/")
                    .maxAge(Duration.ofDays(15))
                    .sameSite("Lax")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

            // 2. Access Token Cookie
            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken)
                    .httpOnly(true) // Consider making this false if client needs access
                    .secure(false)
                    .path("/")
                    .maxAge(Duration.ofMinutes(5)) // Matches access token expiration
                    .sameSite("Lax")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());

            // 3. Fingerprint Cookie
            ResponseCookie fingerprintCookie = ResponseCookie.from("fingerprint", fingerprint)
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .maxAge(Duration.ofDays(15))
                    .sameSite("Strict") // Extra protection for fingerprint
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, fingerprintCookie.toString());

            logger.info("[AuthService] Set 3 auth cookies successfully");

        } catch (Exception e) {
            logger.error("[AuthService] Cookie setting failed: {}", e.getMessage());
            response.addHeader("X-Cookie-Error", e.getMessage());
        }
    }

    private AuthResponseDto generateTokensAndCookies(UserEntity user,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            String username = user.getEmail();

            // Check if user is blocked
            if (loginAttemptService.isBlocked(username)) {
                throw new AuthenticationException(ErrorCode.ACCOUNT_BLOCKED, "Account blocked");
            }

            // Create authentication object
            List<GrantedAuthority> authorities = getAuthorities(user);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authorities);

            // Generate fingerprint
            String fingerprintHash = fingerprintUtil.generateFingerprint(request, username);

                // Create a session and generate tokens
                String sessionId = java.util.UUID.randomUUID().toString();

                UserSession session = new UserSession();
                session.setSessionId(sessionId);
                session.setUserId(user.getId());
                session.setStatus("ACTIVE");
                try {
                session.setIpAddress(request.getRemoteAddr());
                } catch (Exception ignored) {
                }
                userSessionRepository.save(session);

                String accessToken = jwtTokenGenerator.generateAccessToken(
                    authentication,
                    user.getId(),
                    user.getEmail(),
                    fingerprintHash,
                    sessionId);

                String refreshToken = jwtTokenGenerator.generateRefreshToken(
                    authentication,
                    user.getId(),
                    fingerprintHash,
                    sessionId);

            // Save refresh token
            saveUserRefreshToken(user, refreshToken);

            // Set refresh token cookie
            setRefreshTokenCookie(response, refreshToken);

            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .accessTokenExpiry(5 * 60) // 5 minutes
                    .fingerprint(fingerprintHash)
                    .userName(user.getEmail())
                    .build();

        } catch (Exception e) {
            logger.error("[AuthService:generateTokensAndCookies] Error generating tokens: {}", e.getMessage(), e);
            throw new AuthenticationException(ErrorCode.INVALID_CREDENTIALS, "Token generation failed");
        }
    }

    @Override
    public ApiResponseDto<String> resetForgottenPassword(String usernameOrEmail, String otp, String newPassword) {
        try {
            logger.info("[AuthService:resetForgottenPassword] Password reset requested for: {}", usernameOrEmail);

            // First verify the OTP
            ApiResponseDto<String> verificationResult = verifyOtp(usernameOrEmail, otp);
            if (!verificationResult.isSuccess()) {
                return verificationResult;
            }

            // Find the user
            Optional<UserEntity> userOptional = userInfoRepo.findByEmail(usernameOrEmail);
            if (userOptional.isEmpty()) {
                userOptional = userInfoRepo.findByEmail(usernameOrEmail);
            }

            UserEntity user = userOptional.get(); // Safe to get as we already verified user exists

            // Check if LDAP authentication is enabled for this user
            boolean isLdapAuth = "ldap".equalsIgnoreCase(authenticationMethod);
            if (isLdapAuth) {
                return new ApiResponseDto<>(
                        false,
                        HttpStatus.BAD_REQUEST.value(),
                        "Password reset is not available for LDAP users. Please contact your system administrator.",
                        null,
                        new ApiResponseDto.ErrorDetails2(1008));
            }

            // Clear OTP data
            user.setOtp(null);
            user.setOtpExpiry(null);

            userInfoRepo.save(user);

            return new ApiResponseDto<>(
                    true,
                    HttpStatus.OK.value(),
                    "Password reset successful. You can now login with your new password.",
                    null);
        } catch (Exception e) {
            logger.error("[AuthService:resetForgottenPassword] Error resetting password: {}", e.getMessage());
            return new ApiResponseDto<>(
                    false,
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "An error occurred while resetting password: " + e.getMessage(),
                    null,
                    new ApiResponseDto.ErrorDetails2(1011));
        }
    }

    /**
     * Sync user data to Main Service after successful registration/OTP verification.
     * This creates the user in Main Service.
     * 
     * @param user The user entity to sync
     * @return true if sync was successful, false otherwise
     */
    @Override
    public ApiResponseDto<Object> setupPin(UUID userId, String pinHash) {
        try {
            UserEntity user = userInfoRepo.findById(userId)
                    .orElse(null);
            if (user == null) {
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(), "User not found", null);
            }
            user.setPinHash(pinHash);
            userInfoRepo.save(user);
            logger.info("[AuthService:setupPin] PIN set successfully for userId={}", userId);
            return new ApiResponseDto<>(true, HttpStatus.OK.value(), "PIN set successfully", null);
        } catch (Exception e) {
            logger.error("[AuthService:setupPin] Error setting PIN for userId={}: {}", userId, e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to set PIN", null);
        }
    }

    @Override
    public ApiResponseDto<Object> verifyPin(UUID userId, String pinHash) {
        try {
            UserEntity user = userInfoRepo.findById(userId)
                    .orElse(null);
            if (user == null) {
                return new ApiResponseDto<>(false, HttpStatus.NOT_FOUND.value(), "User not found", null);
            }
            if (user.getPinHash() == null || user.getPinHash().isEmpty()) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(), "No PIN set for this user", null);
            }
            if (user.getPinHash().equals(pinHash)) {
                logger.info("[AuthService:verifyPin] PIN verified successfully for userId={}", userId);
                return new ApiResponseDto<>(true, HttpStatus.OK.value(), "PIN verified successfully", null);
            } else {
                logger.warn("[AuthService:verifyPin] Incorrect PIN for userId={}", userId);
                return new ApiResponseDto<>(false, HttpStatus.UNAUTHORIZED.value(), "Incorrect PIN", null);
            }
        } catch (Exception e) {
            logger.error("[AuthService:verifyPin] Error verifying PIN for userId={}: {}", userId, e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to verify PIN", null);
        }
    }

    private boolean syncUserToMainService(UserEntity user) {
        try {
            logger.info("[AuthService:syncUserToMainService] Syncing user to Main Service: userId={}, email={}", 
                    user.getId(), user.getEmail());

            String syncUrl = mainServiceUrl + "/router-backend/user/sync-user";

            // Build sync request payload
            Map<String, Object> syncRequest = new HashMap<>();
            syncRequest.put("userId", user.getId());
            syncRequest.put("email", user.getEmail());
            syncRequest.put("userName", user.getName());
            syncRequest.put("mobileNumber", user.getMobileNumber());
            syncRequest.put("status", user.getIsActive());

            logger.info("[AuthService:syncUserToMainService] Sending sync request to: {} with payload: {}", 
                    syncUrl, syncRequest);

            // Make HTTP call to Main Service
            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);

            org.springframework.http.HttpEntity<Map<String, Object>> requestEntity = 
                    new org.springframework.http.HttpEntity<>(syncRequest, headers);

            org.springframework.http.ResponseEntity<Map> responseEntity = restTemplate.exchange(
                    syncUrl,
                    org.springframework.http.HttpMethod.POST,
                    requestEntity,
                    Map.class
            );

            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                Map responseBody = responseEntity.getBody();
                boolean success = responseBody != null && Boolean.TRUE.equals(responseBody.get("success"));
                
                if (success) {
                    logger.info("[AuthService:syncUserToMainService] User synced successfully to Main Service. " +
                            "userId={}, Main Service synced", user.getId());
                } else {
                    logger.warn("[AuthService:syncUserToMainService] Main Service returned success=false. " +
                            "Response: {}", responseBody);
                }
                return success;
            } else {
                logger.error("[AuthService:syncUserToMainService] Main Service sync failed. Status: {}, Body: {}", 
                        responseEntity.getStatusCode(), responseEntity.getBody());
                return false;
            }

        } catch (Exception e) {
            logger.error("[AuthService:syncUserToMainService] Error syncing user to Main Service: userId={}, deviceId={}, error={}", 
                    user.getId(), null, e.getMessage(), e);
            // Don't throw - user registration should still succeed even if sync fails
            // The sync can be retried later
            return false;
        }
    }
    @Override
    public ApiResponseDto<Object> setupPassword(PasswordSetupDto dto) {
        try {
            Optional<UserEntity> userOpt = userInfoRepo.findBySetupToken(dto.getToken());
            if (userOpt.isEmpty()) {
                return new ApiResponseDto<>(false, HttpStatus.BAD_REQUEST.value(), "Invalid or expired token", null);
            }
            
            UserEntity user = userOpt.get();
            
            user.setPasswordHash(passwordEncoder.encode(dto.getPassword()));
            user.setSetupToken(null);
            user.setIsActive(true);
            user.setAccountStatus(com.auth.service.entity.AccountStatus.ACTIVE);
            
            userInfoRepo.save(user);
            
            return new ApiResponseDto<>(true, HttpStatus.OK.value(), "Password setup successfully. You can now log in.", null);
        } catch (Exception e) {
            logger.error("Error in setupPassword: {}", e.getMessage());
            return new ApiResponseDto<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "An unexpected error occurred", null);
        }
    }
}
