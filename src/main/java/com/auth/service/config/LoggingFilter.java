package com.auth.service.config;

import com.auth.service.logger.LogContext;
import com.auth.service.util.UserUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Optional filter to set up logging context fallback values at the beginning of each request.
 * This is only needed for requests that don't go through the JWT authentication filter.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoggingFilter extends OncePerRequestFilter {

    private final UserUtil userUtil;

    @Autowired
    public LoggingFilter(UserUtil userUtil) {
        this.userUtil = userUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // Set up fallback logging context for non-authenticated requests
            String correlationId = request.getHeader("X-Correlation-Id");
            if (correlationId == null || correlationId.isEmpty()) {
                correlationId = userUtil.generateCorrelationId();
            }
            LogContext.setCorrelationId(correlationId);

            // Continue with the request
            filterChain.doFilter(request, response);
        } finally {
            // Clear the context after the request is processed
            LogContext.clear();
        }
    }
}

