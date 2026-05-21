package com.auth.service;

import com.auth.service.config.user.UserConfig;
import com.auth.service.config.user.UserManagerConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;

@Configuration
public class AuthDebugRunner {

    @Autowired
    private UserManagerConfig userManagerConfig;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner debugAuth() {
        return args -> {
            System.out.println("====== AUTH DEBUG START ======");
            try {
                UserDetails userDetails = userManagerConfig.loadUserByUsername("superadmin@browns.com");
                System.out.println("Loaded user: " + userDetails.getUsername());
                System.out.println("Password hash from UserDetails: " + userDetails.getPassword());
                
                String rawPassword = "SuperAdmin@123";
                boolean matches = passwordEncoder.matches(rawPassword, userDetails.getPassword());
                System.out.println("Matches 'SuperAdmin@123': " + matches);
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("====== AUTH DEBUG END ======");
        };
    }
}
