package com.cos.security1.domain.email.service;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.dto.EmailAddDto;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.user.dto.UserSignDto;
import com.cos.security1.domain.user.entity.Role;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class EmailService {

    private final UserRepository userRepository;
    private final EmailRepository emailRepository;
    private final PasswordEncoder passwordEncoder;

    // 첫번째 파라미터인 email 은 처음에 회원가입한 email 이다.
    public void addEmail(String email, EmailAddDto emailAddDto) throws Exception {

        Optional<User> joinEmail = userRepository.findByEmail(email);
        if (joinEmail.isEmpty()) {
            throw new Exception("가입되지 않은 이메일입니다.");
        }
        log.info("joinEmail: {}", joinEmail);

        Optional<Email> registeredEmail = emailRepository.findByEmail(emailAddDto.getEmail());

        if (registeredEmail.isPresent()) {
            throw new Exception("이미 등록된 이메일입니다.");
        } else {
            Email entity = Email.builder()
                    .email(emailAddDto.getEmail())
                    .role(Role.USER)
                    .nickname(joinEmail.get().getNickname())
                    .user(joinEmail.get())
                    .build();
            emailRepository.save(entity);
            joinEmail.get().addEmail(entity);
            userRepository.saveAndFlush(joinEmail.get());
        }
    }
}
