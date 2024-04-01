package com.cos.security1.domain.email.repository;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.user.entity.SocialType;
import com.cos.security1.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface EmailRepository extends JpaRepository<Email, Long> {

    Optional<Email> findById(Long id);
    List<Email> findByNickname(String nickname);

    Optional<Email> findByEmail(String email);

    Optional<Email> findByRefreshToken(String refreshToken);
    Optional<Email> findBySocialTypeAndSocialId(SocialType socialType, String socialId);

}
