package com.cos.security1.domain.user.controller;

import com.cos.security1.domain.email.service.EmailService;
import com.cos.security1.domain.user.dto.LoginForm;
import com.cos.security1.domain.user.dto.UserSignDto;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final EmailService emailService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private static final String GOOGLE_LOGIN_FORM = "/oauth2/authorization/google";



//    @GetMapping("/sign-up")
//    public String signUp() {
//        return "signUp";
//    }

    @PostMapping("/sign-up")
    public ResponseEntity<UserSignDto> signUp(@RequestBody UserSignDto userSignDto, HttpServletResponse response) throws Exception {
        userService.signUp(userSignDto);
        response.sendRedirect("/home");
        return ResponseEntity.ok(userSignDto);
    }

//    @GetMapping("/securitycontext")
//    public ResponseEntity confirm() {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        log.info("authentcation: {}", authentication.getName());
//        log.info("authentcation: {}", authentication.getAuthorities());
//        log.info("authentcation: {}", authentication.getCredentials());
//        log.info("authentcation: {}", authentication.getDetails());
//        log.info("authentcation: {}", authentication.getPrincipal());
//
//
//        return ResponseEntity.ok(authentication);
//    }

    @GetMapping("login/google")
    public void addEmail(HttpServletResponse response) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.isAuthenticated() && authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient("google", authentication.getName());
            if (authorizedClient != null) {
                response.sendRedirect("/oauth2/authorization/google?prompt=select_account");
            }
            return;
        }
        response.sendRedirect("/oauth2/authorization/google?prompt=select_account");
    }

    @ResponseBody
    @GetMapping("/user/info")
    public String userInfo(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails != null) {
            // 사용자가 로그인한 상태

            String username = userDetails.getUsername();
            log.info("로그인 상태임, {}", username);
            // 추가적인 사용자 정보 처리...
        } else {
            log.info("로그인 상태가 아님");
            // 사용자가 로그인하지 않은 상태
        }
        return "userInfo";
    }


//    @GetMapping("/login")
//    public String login() {
//        return "login";
//    }
//
//    @PostMapping("/login")
//    public User login(LoginForm loginForm) throws Exception {
//        return userService.login(loginForm);
//
//    }

    @ResponseBody
    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청 성공";
    }

//    @GetMapping("/home")
//    public String home() {
//        return "home";
//    }
}
