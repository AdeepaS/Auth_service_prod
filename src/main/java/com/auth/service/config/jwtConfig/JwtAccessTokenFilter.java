package com.auth.service.config.jwtConfig;

import com.auth.service.config.RSAKeyRecord;
import com.auth.service.dto.TokenType;
import com.auth.service.logger.LoggerAdapter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import com.auth.service.entity.UserSession;
import com.auth.service.repository.UserSessionRepository;
import java.util.List;

@RequiredArgsConstructor
public class JwtAccessTokenFilter extends OncePerRequestFilter {

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final LoggerAdapter logger;

    private final UserSessionRepository userSessionRepository;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/Authservice/auth/api/create/user") ||
               path.equals("/Authservice/auth/verify-otp") ||
               path.equals("/Authservice/auth/resend-otp") ||
               path.equals("/Authservice/auth/sign-up") ||
               path.equals("/Authservice/auth/login") ||
               path.equals("/Authservice/auth/sign-in");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String correlationId = null;
        String sessionId = null;
        logger.info("Access Token filtering stating.....");
        try {
            // Retrieve Authorization Header and Correlation ID
            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            correlationId = request.getHeader("X-Correlation-Id");

            // Generate a new Correlation ID if missing
            if (correlationId == null || correlationId.isEmpty()) {
                correlationId = java.util.UUID.randomUUID().toString();
                logger.info("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Generated new Correlation ID: {}", "Creating.." ,correlationId , "Filtering..");
            }

            // Validate Authorization Header
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                logger.warn("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Missing or invalid Authorization header", "Creating.." ,correlationId , "Filtering..");
                sendUnauthorizedResponse(response, "Unauthorized: Token is missing or invalid.");
                return;
            }

            // Extract and Decode the JWT Token
            final String token = authHeader.substring(7);
            
            String plainJwt;
            // Check if it is already a plain JWT (3 dot-separated parts)
            boolean isJwtFormat = token.contains(".") && token.split("\\.").length == 3;
            if (isJwtFormat) {
                plainJwt = token;
                logger.info("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Token is already a plain JWT. Skipping decryption.", "Creating..", correlationId, "Filtering..");
            } else {
                // Decipher the token
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
                com.google.crypto.tink.KeysetHandle keysetHandle =
                        com.google.crypto.tink.CleartextKeysetHandle.read(
                                com.google.crypto.tink.JsonKeysetReader.withString(keyJson));
                com.auth.service.util.TokenCipher tokenCipher = new com.auth.service.util.TokenCipher();
                plainJwt = tokenCipher.decipherToken(token, keysetHandle);
                logger.info("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Successfully deciphered Tink token.", "Creating..", correlationId, "Filtering..");
            }

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final Jwt jwtToken = jwtDecoder.decode(plainJwt);
            String userId1Str = jwtToken.getClaim("user_id");
            java.util.UUID userId1 = userId1Str != null ? java.util.UUID.fromString(userId1Str) : null;
            sessionId = jwtToken.getClaim("sessionId");

            // Validate session against DB
            if (sessionId == null || sessionId.isEmpty()) {
                logger.warn("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Missing sessionId claim", sessionId, correlationId, userId1);
                sendUnauthorizedResponse(response, "Unauthorized: Missing session.");
                return;
            }

            java.util.Optional<UserSession> sessionOpt = userSessionRepository.findFirstBySessionIdAndStatus(sessionId, "ACTIVE");
            if (sessionOpt.isEmpty()) {
                logger.warn("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Session not ACTIVE or not found", sessionId, correlationId, userId1);
                sendUnauthorizedResponse(response, "Unauthorized: Session is not active.");
                return;
            }
            logger.info("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Received from BFF", sessionId, correlationId , userId1);
            logger.info("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Filtering the HTTP Request: {} ",sessionId , correlationId , userId1, request.getRequestURI());
            logger.info("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Successfully decoded JWT Token ", sessionId ,correlationId , userId1);

            // Ensure Security Context is Empty
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                // Extract Claims
                String email = jwtToken.getClaimAsString("email");
                String userIdStr = jwtToken.getClaim("user_id");
                java.util.UUID userId = userIdStr != null ? java.util.UUID.fromString(userIdStr) : null;
                Long roleId = jwtToken.getClaim("roleId");
                List<String> permissions = jwtToken.getClaimAsStringList("scope");
                List<String> roles = jwtToken.getClaimAsStringList("roles");

                // Validate Required Claims
                if (email == null || email.isEmpty() || userId == null || permissions == null || roleId == null ||
                    sessionId == null || sessionId.isEmpty()) {
                    logger.warn("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Missing required claims in JWT Token", sessionId ,correlationId , userId);
                    logger.debug("SessionId: {}, correlation ID: {} [JwtAccessTokenFilter:doFilterInternal] Missing claims - email: {}", sessionId, correlationId, email == null ? "null" : "present");
                    sendUnauthorizedResponse(response, "Unauthorized: Missing required claims.");
                    return;
                }

                // Create Authentication Token
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        email,
                        null,
                        jwtTokenUtils.createAuthorities(roleId, permissions, roles)
                );

                // Add Custom Authentication Details
                CustomAuthenticationDetails customDetails = new CustomAuthenticationDetails(request, correlationId, sessionId , userId);
                request.setAttribute("CUSTOM_AUTH_DETAILS", customDetails);
                authenticationToken.setDetails(customDetails);

                // Set Security Context
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authenticationToken);
                SecurityContextHolder.setContext(securityContext);
                logger.info("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Security context updated successfully", sessionId ,correlationId , "Filtering..");
            }

            // Proceed with the filter chain
            filterChain.doFilter(request, response);

        } catch (JwtValidationException jwtValidationException) {
            logger.error("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] JWT Validation Exception: {}", sessionId ,correlationId , "Filtering.." ,jwtValidationException.getMessage());
            sendUnauthorizedResponse(response, "Token expired or invalid. Please re-authenticate.");
        } catch (Exception ex) {
            logger.error("SessionId: {}, correlation ID: {} , userId: {} [JwtAccessTokenFilter:doFilterInternal] Unexpected exception: {} for correlation ID: {}", sessionId ,correlationId , "Filtering..",ex.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            String responseBody = "{\"success\": false, \"statusCode\": 500, \"message\": \"An unexpected error occurred.\", \"data\": null}";
            response.getWriter().write(responseBody);
            response.getWriter().flush();
        }
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        String responseBody = String.format("{\"success\": false, \"statusCode\": 401, \"message\": \"%s\", \"data\": null}", message);
        response.getWriter().write(responseBody);
        response.getWriter().flush();
    }

    // No MD5-based pseudo session anymore; session is a stable DB record.
}
