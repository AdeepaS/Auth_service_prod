package com.auth.service.config.jwtConfig;

import com.auth.service.config.RSAKeyRecord;
import com.auth.service.entity.RefreshTokenEntity;
import com.auth.service.logger.LoggerAdapter;
import com.auth.service.repository.RefreshTokenRepo;
import com.auth.service.repository.UserRepo;
import com.auth.service.config.user.UserConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class JwtTokenUtils {

    private final UserRepo userRepo;
    private final RefreshTokenRepo refreshTokenRepo;
    private final RSAKeyRecord rsaKeyRecord;
    private final LoggerAdapter logger;

    public String getUserName(Jwt jwtToken){
        return jwtToken.getSubject();
    }

    public String getEmail(Jwt jwtToken) {
        return jwtToken.getClaim("email");
    }

    public String getRole(Jwt jwtToken) {
        Object claim = jwtToken.getClaim("roles");
        if (claim instanceof String roleString) {
            return roleString;
        }
        if (claim instanceof List<?> list && !list.isEmpty()) {
            Object first = list.get(0);
            return first != null ? first.toString() : null;
        }
        return null;
    }

//    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails){    //check Token username is same or not in the DB username
//        final String userName = getUserName(jwtToken);
//        boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
//        boolean isTokenUserSameAsDatabase = userName.equals(userDetails.getUsername());
//        return !isTokenExpired  && isTokenUserSameAsDatabase;
//
//    }

    public boolean isTokenValid(Jwt jwtToken , UserDetails userDetails) {
        // Extract the username from the JWT access token
        final String userName = getUserName(jwtToken);

        // Extract the user ID from the JWT access token
        final String userIdStr = jwtToken.getClaim("user_id");
        final java.util.UUID userId = userIdStr != null ? java.util.UUID.fromString(userIdStr) : null;  // Assuming 'user_id' is stored in the JWT claim

        // Check if the token is expired
        boolean isTokenExpired = getIfTokenIsExpired(jwtToken);

        // Check if the username in the JWT token matches the username from the UserDetails
        boolean isTokenUserSameAsDatabase = userName.equals(userName);

        // Retrieve the refresh tokens from the database for the given user ID
        List<RefreshTokenEntity> storedRefreshTokens = refreshTokenRepo.findByUserId(userId);

        // Check if any of the refresh tokens are revoked
        boolean isAnyRefreshTokenRevoked = storedRefreshTokens.stream()
                .anyMatch(token -> token.isRevoked());  // Returns true if any token is revoked

        // If the token is expired, or the user is not the same, or any of the refresh tokens are revoked, return false
        return !isTokenExpired && isTokenUserSameAsDatabase && !isAnyRefreshTokenRevoked;
    }

    private boolean getIfTokenIsExpired(Jwt jwtToken) {
        return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
    }

    public UserDetails userDetails(String emailId){
        return userRepo
                .findByEmail(emailId)
                .map(UserConfig::new)
                .orElseThrow(()-> new UsernameNotFoundException("UserEmail: "+emailId+" does not exist"));
    }

    public Long GetUserWorkFlowRoleId(String token){
        try {
            JwtDecoder jwtDecoder =  NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final Jwt jwtToken = jwtDecoder.decode(token);
            final Long workFlowRoleId = getWorkFlowRoleId(jwtToken);
            return workFlowRoleId;
        } catch (Exception e){
            logger.error("[PermissionServiceImpl:GetUserRole] Error extract the user work flow role Id :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Please Try Again");
        }
    }

    public Long GetUserRoleId(String token){
        try {
            JwtDecoder jwtDecoder =  NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final Jwt jwtToken = jwtDecoder.decode(token);
            final Long role = getRoleId(jwtToken);
            return role;
        } catch (Exception e){
            logger.error("[PermissionServiceImpl:GetUserRole] Error extract the user role :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Please Try Again");
        }
    }

    public Long getRoleId(Jwt jwtToken) {
        return jwtToken.getClaim("roleId");
    }

    public Long getWorkFlowRoleId(Jwt jwtToken) {
        return jwtToken.getClaim("workFlowRoleId");
    }

    public List<GrantedAuthority> createAuthorities(Long roleId, List<String> permissions, List<String> roles) {
        return Stream.concat(
            Stream.concat(
                Stream.of(new SimpleGrantedAuthority("ROLE_ID_" + roleId)),
                permissions.stream().map(SimpleGrantedAuthority::new)
            ),
            roles == null ? Stream.empty() : roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r))
        ).collect(Collectors.toList());
    }
}

