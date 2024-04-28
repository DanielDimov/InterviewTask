package com.danieldimov.interviewtask;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class InterviewTaskApplication {

    public static final String[] OPEN_URLS = {
            "/",
            "/index.html", "/*.js", "/*.css", "/*.svg", "/favicon.ico", "/*.txt",
            "/swagger-ui/**", "/api-docs/**",
            "/image/**",
            "/assets/**",
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/register",
    };

    public static final String API_URL_PATTERN = "/api/**";

    public static void main(String[] args) {
        SpringApplication.run(InterviewTaskApplication.class, args);
    }

}