package com.auth.service.config;

import com.auth.service.logger.LoggerAdapter;
import com.auth.service.logger.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoggerConfig {

    private final LoggerFactory loggerFactory;

    public LoggerConfig(LoggerFactory loggerFactory) {
        this.loggerFactory = loggerFactory;
    }

    @Bean
    public LoggerAdapter loggerAdapter() {
        return loggerFactory.createLoggerAdapter();
    }
}
