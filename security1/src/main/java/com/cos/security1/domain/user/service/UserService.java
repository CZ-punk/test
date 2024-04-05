package com.cos.security1.domain.user.service;

import com.cos.security1.domain.user.dto.LoginForm;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.dto.UserSignDto;
import com.cos.security1.domain.user.entity.Role;
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
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(UserSignDto userSignDto) throws Exception {

        if (userRepository.findByEmail(userSignDto.getEmail()).isPresent()) {
            throw new Exception("이미 존재하는 이메일입니다.");
        }

        if (userRepository.findByNickname(userSignDto.getNickname()).isPresent()) {
            throw new Exception("이미 존재하는 닉네임입니다.");
        }

        User user = User.builder()
                .email(userSignDto.getEmail())
                .password(userSignDto.getPassword())
                .nickname(userSignDto.getNickname())
                .role(Role.USER)
                .build();
        log.info("user: {}", user);

        user.passwordEncode(passwordEncoder);
        userRepository.save(user);
    }

    public User login(LoginForm loginForm) throws Exception {

        Optional<User> findLogin = userRepository.findByEmailAndPassword(loginForm.getEmail(), loginForm.getPassword());

        if (findLogin.isEmpty()) {
            throw new Exception("존재하지 않는 유저입니다.\nEmail 과 Password 를 다시 확인해보세요.");
        }



        return findLogin.get();
    }



}
