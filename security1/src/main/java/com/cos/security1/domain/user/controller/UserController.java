package com.cos.security1.domain.user.controller;

import com.cos.security1.domain.user.dto.UserSignDto;
import com.cos.security1.domain.user.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private static final String GOOGLE_LOGIN_FORM = "/oauth2/authorization/google";

    @ResponseBody
    @PostMapping("/sign-up")
    public String signUp(@RequestBody UserSignDto userSignDto) throws Exception {
        userService.signUp(userSignDto);
        return "회원가입 성공";
    }

    @GetMapping("/login/google")
    public void redirectGoogleLoginForm(HttpServletResponse response) throws IOException {
        response.sendRedirect(GOOGLE_LOGIN_FORM);
    }

    @ResponseBody
    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청 성공";
    }

//    @GetMapping("/loginForm")
//    public String loginForm() {
//        return "home";
//    }
//
//    @GetMapping("/loginSuccess")
//    @ResponseBody
//    public String success() {
//        return "Login Success";
//    }



}
