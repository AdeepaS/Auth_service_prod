package com.auth.service;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class GenHashRunner {

    @Bean
    public CommandLineRunner genHash(PasswordEncoder passwordEncoder) {
        return args -> {
            System.out.println("====== GEN HASH START ======");
            String hash = passwordEncoder.encode("admin123");
            System.out.println("CORRECT HASH FOR admin123: " + hash);
            System.out.println("====== GEN HASH END ======");
        };
    }
}
