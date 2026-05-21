package com.auth.service;

import com.auth.service.repository.UserRepo;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DebugRunner {

    @Bean
    public CommandLineRunner run(UserRepo userRepo) {
        return args -> {
            System.out.println("====== DEBUG START ======");
            userRepo.findByEmail("superadmin@browns.com").ifPresentOrElse(
                user -> System.out.println("Super Admin hash in DB: " + user.getPasswordHash()),
                () -> System.out.println("Super Admin user NOT FOUND")
            );
            System.out.println("====== DEBUG END ======");
        };
    }
}
