package com.auth.service.config.jwtConfig;

import java.util.UUID;

import com.auth.service.util.TokenCipher;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtTokenGenerator {
    private static final Logger log = LoggerFactory.getLogger(JwtTokenGenerator.class);

    @Autowired
    private JwtEncoder jwtEncoder;

    @Value("${ciphering.key.path}")
    private String keyCipheringPath;

    /**
     * Generate an access token with fingerprint hash and sessionId included in the claims
     */
    public String generateAccessToken(Authentication authentication,
                                      UUID userId,
                                      String email,
                                      String fingerprintHash,
                                      String sessionId) {
        log.info("[JwtTokenGenerator:generateAccessToken] Token Creation Started for:{}", authentication.getName());

        String role = resolveRole(authentication);
        Long roleId = mapRoleToId(role);
        List<String> permissions = getPermissionsFromRoles(roleId);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("atquil")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(1, ChronoUnit.DAYS))
                .subject(authentication.getName())
                .claim("user_id", userId)
                .claim("email", email)
            .claim("roles", List.of(role))
            .claim("roleId", roleId)
            .claim("scope", permissions)
            .claim("fingerprint", fingerprintHash)
            .claim("sessionId", sessionId)
                .build();

        String jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        // Embed the key JSON directly in the code
        KeysetHandle keyCiphering = null;
        try {
            String keyJson = "{"
                    + "\"primaryKeyId\":339737423,"
                    + "\"key\":["
                    + "  {"
                    + "    \"keyData\":{"
                    + "      \"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\","
                    + "      \"value\":\"GiCdyK5Sr8dC9PfXKRxfyYWR9sl5DgejhdsojzoYJ76PGA==\","
                    + "      \"keyMaterialType\":\"SYMMETRIC\""
                    + "    },"
                    + "    \"status\":\"ENABLED\","
                    + "    \"keyId\":339737423,"
                    + "    \"outputPrefixType\":\"TINK\""
                    + "  }"
                    + "]"
                    + "}";

            // Use JsonKeysetReader with a string instead of a file
            keyCiphering = CleartextKeysetHandle.read(JsonKeysetReader.withString(keyJson));
        } catch (GeneralSecurityException | IOException e) {
            log.error("Error loading keyset for ciphering", e);
            throw new RuntimeException("Error loading keyset for ciphering", e);
        }

        // Initialize the token cipher
        TokenCipher tokenCipher;
        try {
            tokenCipher = new TokenCipher();
        } catch (Exception e) {
            log.error("Error initializing token cipher", e);
            throw new RuntimeException("Error initializing token cipher", e);
        }

        // Cipher the token
        String cipheredToken;
        try {
            cipheredToken = tokenCipher.cipherToken(jwt, keyCiphering);
        } catch (Exception e) {
            log.error("Error ciphering token", e);
            throw new RuntimeException("Error ciphering token", e);
        }

        log.debug("Ciphered Token generated successfully");
        return cipheredToken;
    }

    /**
     * Generate a refresh token (unchanged from original implementation)
     */
    /**
     * Generate a refresh token with ciphering
     */
    public String generateRefreshToken(Authentication authentication,
                                       UUID userId,
                                       String fingerprintHash,
                                       String sessionId) {
        // Existing implementation for JWT claims
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("atquil")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.DAYS))
                .subject(authentication.getName())
                .claim("scope", "REFRESH_TOKEN")
                .claim("fingerprint", fingerprintHash)
            .claim("user_id", userId)
            .claim("sessionId", sessionId)
                .build();

        // Generate the JWT token
        String jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        // Load the keyset for ciphering
        KeysetHandle keyCiphering = null;
        try {
            String keyJson = "{"
                    + "\"primaryKeyId\":339737423,"
                    + "\"key\":["
                    + "  {"
                    + "    \"keyData\":{"
                    + "      \"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\","
                    + "      \"value\":\"GiCdyK5Sr8dC9PfXKRxfyYWR9sl5DgejhdsojzoYJ76PGA==\","
                    + "      \"keyMaterialType\":\"SYMMETRIC\""
                    + "    },"
                    + "    \"status\":\"ENABLED\","
                    + "    \"keyId\":339737423,"
                    + "    \"outputPrefixType\":\"TINK\""
                    + "  }"
                    + "]"
                    + "}";

            // Use JsonKeysetReader with a string instead of a file
            keyCiphering = CleartextKeysetHandle.read(JsonKeysetReader.withString(keyJson));
        } catch (GeneralSecurityException | IOException e) {
            log.error("Error loading keyset for ciphering", e);
            throw new RuntimeException("Error loading keyset for ciphering", e);
        }

        // Initialize the token cipher
        TokenCipher tokenCipher;
        try {
            tokenCipher = new TokenCipher();
        } catch (Exception e) {
            log.error("Error initializing token cipher", e);
            throw new RuntimeException("Error initializing token cipher", e);
        }

        // Cipher the token
        String cipheredRefreshToken;
        try {
            cipheredRefreshToken = tokenCipher.cipherToken(jwt, keyCiphering);
        } catch (Exception e) {
            log.error("Error ciphering token", e);
            throw new RuntimeException("Error ciphering token", e);
        }

        log.info("Ciphered Refresh Token generated successfully");
        return cipheredRefreshToken;
    }

    private String resolveRole(Authentication authentication) {
        if (authentication == null || authentication.getAuthorities() == null) {
            return "USER";
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String auth = authority.getAuthority();
            if (auth != null && auth.startsWith("ROLE_")) {
                return auth.substring("ROLE_".length());
            }
        }
        return "USER";
    }

    private Long mapRoleToId(String role) {
        if ("ADMIN".equalsIgnoreCase(role)) {
            return 3L;
        }
        if ("CUSTOMER_CARE".equalsIgnoreCase(role)) {
            return 2L;
        }
        return 1L; // USER or default
    }

    private List<String> getPermissionsFromRoles(Long roleId) {
        Set<String> permissions = new HashSet<>();
        // Simple mapping: USER -> READ, CUSTOMER_CARE -> READ/WRITE, ADMIN -> READ/WRITE/DELETE
        if (roleId == 1L) {
            permissions.add("READ");
        } else if (roleId == 2L) {
            permissions.addAll(List.of("READ", "WRITE"));
        } else if (roleId == 3L) {
            permissions.addAll(List.of("READ", "WRITE", "DELETE"));
        }
        return List.copyOf(permissions);
    }

}
