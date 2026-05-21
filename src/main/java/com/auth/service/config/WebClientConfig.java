package com.auth.service.config;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Configuration for WebClient and RestTemplate to communicate with Main Service
 */
@Configuration
public class WebClientConfig {

        @Value("${main.service.url:http://localhost:8081}")
        private String mainServiceUrl;

        @Value("${main.service.connection.timeout:5000}")
        private int connectionTimeout;

        @Value("${main.service.read.timeout:10000}")
        private int readTimeout;

        @Bean
        public WebClient mainServiceWebClient() {
                HttpClient httpClient = HttpClient.create()
                                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectionTimeout)
                                .responseTimeout(Duration.ofMillis(readTimeout))
                                .doOnConnected(conn -> conn
                                                .addHandlerLast(new ReadTimeoutHandler(readTimeout,
                                                                TimeUnit.MILLISECONDS))
                                                .addHandlerLast(new WriteTimeoutHandler(readTimeout,
                                                                TimeUnit.MILLISECONDS)));

                return WebClient.builder()
                                .baseUrl(mainServiceUrl)
                                .clientConnector(new ReactorClientHttpConnector(httpClient))
                                .build();
        }


}
