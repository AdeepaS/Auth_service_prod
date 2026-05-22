package com.auth.service.repository;

import com.auth.service.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepo extends JpaRepository<UserEntity, UUID> {

    Optional<UserEntity> findByEmail(String email);

    Optional<UserEntity> findByMobileNumber(String mobileNumber);

    Optional<UserEntity> findByNameAndOtp(String name, String otp);

    Optional<UserEntity> findByEmailAndOtp(String email, String otp);

    boolean existsByEmailAndIsActive(String email, Boolean isActive);

    boolean existsByMobileNumberAndIsActive(String mobileNumber, Boolean isActive);

    boolean existsByEmail(String email);
    
    Optional<UserEntity> findBySetupToken(String setupToken);

    java.util.List<UserEntity> findByAccountStatus(com.auth.service.entity.AccountStatus accountStatus);
}
