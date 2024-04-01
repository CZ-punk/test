package com.cos.security1.domain.user.service;

import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.dto.UserSignDto;
import com.cos.security1.domain.user.entity.Role;
import com.cos.security1.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
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

        user.passwordEncode(passwordEncoder);
        userRepository.save(user);
    }
}
