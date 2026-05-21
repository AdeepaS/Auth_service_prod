package com.auth.service.exception;

import com.auth.service.dto.ApiResponseDto;
import com.auth.service.error.AuthErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiResponseDto<Object>> handleResponseStatusException(ResponseStatusException ex) {
        return ResponseEntity
                .status(ex.getStatusCode())
                .body(new ApiResponseDto<>(
                        false,
                        ex.getStatusCode().value(),
                        ex.getReason(),  // This will be "UserName is already registered."
                        null
                ) {{ setErrorCode(AuthErrorCode.AUTH_P1_UNCLASSIFIED_FAILURE.code()); }});
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDto<Object>> handleGeneralException(Exception ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponseDto<>(
                        false,
                        500,
                        "Unexpected error occurred",
                        null
                ) {{ setErrorCode(AuthErrorCode.AUTH_P2_UNCLASSIFIED_FAILURE.code()); }});
    }

}
