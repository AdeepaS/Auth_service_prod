package com.auth.service.config.jwtConfig;

import com.auth.service.config.RSAKeyRecord;
import com.auth.service.repository.RefreshTokenRepo;
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

@RequiredArgsConstructor
@Slf4j
public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private  final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepo refreshTokenRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            log.info("[JwtRefreshTokenFilter:doFilterInternal] :: Started ");
            log.info("[JwtRefreshTokenFilter:doFilterInternal]Filtering the Http Request:{}", request.getRequestURI());


            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();

            if (!authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }

            final String token = authHeader.substring(7);
            
            String plainJwt;
            // Check if it is already a plain JWT (3 dot-separated parts)
            boolean isJwtFormat = token.contains(".") && token.split("\\.").length == 3;
            if (isJwtFormat) {
                plainJwt = token;
                log.info("[JwtRefreshTokenFilter:doFilterInternal] Token is already a plain JWT. Skipping decryption.");
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
                log.info("[JwtRefreshTokenFilter:doFilterInternal] Successfully deciphered Tink token.");
            }

            final Jwt jwtRefreshToken = jwtDecoder.decode(plainJwt);


            final String userName = jwtTokenUtils.getUserName(jwtRefreshToken);


            if (!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                //Check if refreshToken isPresent in database and is valid
                var isRefreshTokenValidInDatabase = refreshTokenRepo.findByRefreshToken(jwtRefreshToken.getTokenValue())
                        .map(refreshTokenEntity -> !refreshTokenEntity.isRevoked())
                        .orElse(false);

                UserDetails userDetails = jwtTokenUtils.userDetails(userName);
                if (jwtTokenUtils.isTokenValid(jwtRefreshToken, userDetails) && isRefreshTokenValidInDatabase) {
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            log.info("[JwtRefreshTokenFilter:doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        } catch (JwtValidationException jwtValidationException) {
            log.error("[JwtRefreshTokenFilter:doFilterInternal] Exception due to :{}", jwtValidationException.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtValidationException.getMessage());
        } catch (Exception ex) {
            log.error("[JwtRefreshTokenFilter:doFilterInternal] Unexpected exception: {}", ex.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            String responseBody = "{\"success\": false, \"statusCode\": 500, \"message\": \"An unexpected error occurred.\", \"data\": null}";
            response.getWriter().write(responseBody);
            response.getWriter().flush();
        }
    }
}
