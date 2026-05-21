package com.auth.service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponseDto {

    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("message")
    private String message;
    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("user_name")
    private String userName;

    @JsonProperty("user_role_Id")
    private Long userRoleId;

    @JsonProperty("work_flow_role_Id")
    private Long workFlowRoleId;

    private String fingerprint;

    @JsonProperty("refresh_token")
    private String refreshToken;

}
