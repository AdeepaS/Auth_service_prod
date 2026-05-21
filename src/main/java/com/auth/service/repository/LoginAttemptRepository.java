package com.auth.service.repository;

import com.auth.service.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {
    LoginAttempt findByUsername(String username);

    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.username = :username AND l.lastAttemptTime BETWEEN :startTime AND :endTime")
    int countFailedAttemptsWithin(@Param("username") String username,
                                  @Param("startTime") LocalDateTime startTime,
                                  @Param("endTime") LocalDateTime endTime);

}

