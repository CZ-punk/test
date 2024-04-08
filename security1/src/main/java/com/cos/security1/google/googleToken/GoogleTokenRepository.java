package com.cos.security1.google.googleToken;

import com.cos.security1.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface GoogleTokenRepository extends JpaRepository<GoogleTokenDto, Long> {

    Optional<GoogleTokenDto> findByClient(String client);
}
