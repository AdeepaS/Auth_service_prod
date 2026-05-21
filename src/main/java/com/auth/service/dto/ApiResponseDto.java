package com.auth.service.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponseDto<T> {
    private boolean success;
    private int statusCode;
    private String message;
    private T data;
    private ErrorDetails2 errorDetails2;
    private String errorCode;

    public ApiResponseDto(boolean success, int statusCode, String message, T data) {
        this(success, statusCode, message, data, null);
    }

    public ApiResponseDto(boolean success, int statusCode, String message, T data, ErrorDetails2 errorDetails2) {
        this.success = success;
        this.statusCode = statusCode;
        this.message = message;
        this.data = data;
        this.errorDetails2 = errorDetails2;
    }

    @Data
    @NoArgsConstructor
    public static class ErrorDetails {
        private int errorCode;
        private String serviceIdentifier;

        public ErrorDetails(int errorCode, String serviceIdentifier) {
            this.errorCode = errorCode;
            this.serviceIdentifier = serviceIdentifier;
        }
    }

    @Data
    @NoArgsConstructor
    public static class ErrorDetails2 {
        private int errorCode;
        public ErrorDetails2(int errorCode) {
            this.errorCode = errorCode;
        }
    }
}

