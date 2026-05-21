package com.auth.service.repository;

import com.auth.service.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, String> {

    Optional<UserSession> findFirstBySessionIdAndStatus(String sessionId, String status);

}
