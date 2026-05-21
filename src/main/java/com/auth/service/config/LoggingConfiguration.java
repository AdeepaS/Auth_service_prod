package com.auth.service.config;

import com.auth.service.logger.LoggerAdapter;
import com.auth.service.logger.Slf4jAdapter;
import com.auth.service.logger.Log4jAdapter;
import com.auth.service.logger.CustomLoggerAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class LoggingConfiguration {

    @Value("${logging.framework:slf4j}")
    private String loggingFramework;

    @Bean
    @Primary
    public LoggerAdapter enhancedLoggerAdapterDelegate() {
        switch (loggingFramework.toLowerCase()) {
            case "slf4j":
                return new Slf4jAdapter();
            case "log4j":
                return new Log4jAdapter();
            case "custom":
                return new CustomLoggerAdapter();
            default:
                return new Slf4jAdapter(); // Default to SLF4J
        }
    }
}


