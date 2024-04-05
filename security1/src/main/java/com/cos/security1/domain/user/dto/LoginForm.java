package com.cos.security1.domain.user.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class LoginForm {

    private String email;
    private String password;

}
