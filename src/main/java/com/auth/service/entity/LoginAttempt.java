package com.auth.service.entity;

import java.util.UUID;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "login_attempts")
public class LoginAttempt {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private int attemptCount;

    @Column(nullable = false)
    private LocalDateTime lastAttemptTime;

    @Column(nullable = false)
    private boolean blocked;

    @Column
    private LocalDateTime blockExpireTime;

    // Optional link to cloud_audit.request_id for audit traceability
    @Column(name = "request_id", length = 100)
    private String requestId;

}

