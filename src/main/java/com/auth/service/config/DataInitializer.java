package com.auth.service.config;

import com.auth.service.entity.AccountStatus;
import com.auth.service.entity.Role;
import com.auth.service.entity.UserEntity;
import com.auth.service.repository.UserRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {
    
    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    public CommandLineRunner initSuperAdmin(UserRepo userRepo, PasswordEncoder passwordEncoder) {
        return args -> {
            String superAdminEmail = "superadmin@browns.com";
            if (!userRepo.existsByEmail(superAdminEmail)) {
                logger.info("Initializing hardcoded Super Admin account...");
                UserEntity superAdmin = new UserEntity();
                superAdmin.setName("Super Admin");
                superAdmin.setEmail(superAdminEmail);
                superAdmin.setPasswordHash(passwordEncoder.encode("SuperAdmin@123"));
                superAdmin.setRole(Role.SUPER_ADMIN);
                superAdmin.setIsActive(true);
                superAdmin.setAccountStatus(AccountStatus.ACTIVE);
                userRepo.save(superAdmin);
                logger.info("Super Admin account initialized successfully.");
            } else {
                logger.info("Super Admin account already exists.");
            }
        };
    }
}
