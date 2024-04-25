package com.cos.security1.domain.mail;

import com.cos.security1.domain.email.Email;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MailRepository extends JpaRepository<Mail, Long> {

    Optional<Mail> findByMessageId(String messageId);
    boolean existsByMessageId(String messageId);

    Optional<Mail> findByGoogleTokenDto(GoogleTokenDto googleTokenDto);
    Optional<Mail> findByEmail(Email email);
}
