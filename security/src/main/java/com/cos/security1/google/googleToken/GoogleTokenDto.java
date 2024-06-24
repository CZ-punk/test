package com.cos.security1.google.googleToken;

import com.cos.security1.domain.mail.Mail;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.List;

@Entity
@Getter
@Setter
@Slf4j
@NoArgsConstructor
@AllArgsConstructor
public class GoogleTokenDto {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "GOOGLE_TOKEN_DTO_ID")
    private Long id;
    private String accessToken;
    private String refreshToken;
    private Long tokenExpiresAt;
    private String client;

    @OneToMany(mappedBy = "googleTokenDto")
    @JsonManagedReference
    private List<Mail> mail;


    public boolean isTokenExpired() {
        long expiresIn = tokenExpiresAt - System.currentTimeMillis();

        log.info("tokenExpiresAt: {}", tokenExpiresAt);
        log.info("System.currentTimeMillis(): {}", System.currentTimeMillis());

        log .info("expiresIn: {}", expiresIn);


        return expiresIn <= 0;

    }

}
