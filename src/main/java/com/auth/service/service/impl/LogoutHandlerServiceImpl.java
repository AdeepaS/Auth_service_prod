package com.auth.service.service.impl;
import com.auth.service.logger.EnhancedLoggerAdapter;
import com.auth.service.repository.RefreshTokenRepo;
import com.auth.service.service.LogoutHandlerService;
import com.auth.service.entity.UserSession;
import com.auth.service.repository.UserSessionRepository;
import com.auth.service.config.jwtConfig.CustomAuthenticationDetails;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class LogoutHandlerServiceImpl implements LogoutHandlerService {

    private final RefreshTokenRepo refreshTokenRepo;
    private final EnhancedLoggerAdapter logger;
    private final UserSessionRepository userSessionRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        logger.info("Log out starting");
        try {
            // Get the Authorization header from the request
            String RefreshTokenHeader = request.getHeader("refreshToken");
            logger.info("Refresh token header received");

            // Validate the Authorization header
            if (RefreshTokenHeader == null || !RefreshTokenHeader.startsWith("Bearer ")) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or missing Authorization header");
            }

            // Extract the refresh token from the Authorization header
            final String refreshToken = RefreshTokenHeader.substring(7);
            logger.debug("Refresh token extracted from header. Token: {}", maskToken(refreshToken));

            if (refreshToken.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Refresh token is empty");
            }

            // Revoke the refresh token from the repository
            var storedRefreshToken = refreshTokenRepo.findByRefreshToken(refreshToken)
                    .map(token -> {
                        token.setRevoked(true);  // Mark the token as revoked
                        refreshTokenRepo.save(token);  // Save the updated token
                        logger.info("Refresh token revoked successfully");
                        logger.debug("Revoked token: {}", maskToken(refreshToken));
                        return token;
                        })
                        .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Refresh token not found in the database"));

            // Also mark the corresponding session as LOGOUT if possible using the
            // CustomAuthenticationDetails populated by JwtAccessTokenFilter.
            if (authentication != null && authentication.getDetails() instanceof CustomAuthenticationDetails details) {
                String sessionId = details.getSessionId();
                if (sessionId != null && !sessionId.isEmpty()) {
                    userSessionRepository.findById(sessionId).ifPresent(session -> {
                        session.setStatus("LOGOUT");
                        userSessionRepository.save(session);
                        logger.info("Session {} marked as LOGOUT during logout", sessionId);
                    });
                }
            }

            logger.info("Successfully revoked the refresh token");
        } catch (ResponseStatusException ex) {
            logger.error("ResponseStatusException: {}", ex.getMessage());
            throw ex; // Re-throw to ensure correct HTTP response
        } catch (Exception ex) {
            logger.error("Unexpected exception: ", ex);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during logout");
        }
    }

    // Helper method to mask sensitive tokens
    private String maskToken(String token) {
        if (token == null || token.length() < 20) {
            return "***";
        }
        return token.substring(0, 10) + "..." + token.substring(token.length() - 10);
    }



    // Helper method to extract refresh token from cookies
    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh_token".equals(cookie.getName())) {  // Assuming cookie name is 'refresh_token'
                    return cookie.getValue();  // Return the refresh token value
                }
            }
        }
        return null;  // Return null if no refresh token is found
    }
}
