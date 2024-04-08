package com.cos.security1.google.googleToken;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;

@Entity
@Getter
@Setter
@Slf4j
public class GoogleTokenDto {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String accessToken;
    private String refreshToken;
    private Long tokenExpiresAt;
    private String client;

    public boolean isTokenExpired() {
        long expiresIn = tokenExpiresAt - System.currentTimeMillis();

        log.info("tokenExpiresAt: {}", tokenExpiresAt);
        log.info("System.currentTimeMillis(): {}", System.currentTimeMillis());

        log .info("expiresIn: {}", expiresIn);


        return expiresIn <= 0;

    }

}
