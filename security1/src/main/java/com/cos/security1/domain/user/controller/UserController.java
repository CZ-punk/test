package com.cos.security1.domain.user.controller;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.user.dto.LoginForm;
import com.cos.security1.domain.user.dto.UserSignDto;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.domain.user.service.UserService;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import com.cos.security1.google.googleToken.GoogleTokenRepository;
import com.cos.security1.jwt.InMemoryTokenStore;
import com.cos.security1.jwt.JwtService;
import com.cos.security1.oauth2.CustomOAuth2User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final GoogleTokenRepository googleTokenRepository;
    private final InMemoryTokenStore tokenStore;
    private final EmailRepository emailRepository;
    private final UserRepository userRepository;

    private static final String GOOGLE_LOGIN_FORM = "/oauth2/authorization/google";

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @PostMapping("/sign-up")
    public ResponseEntity<UserSignDto> signUp(@RequestBody UserSignDto userSignDto) throws Exception {
        userService.signUp(userSignDto);
        return ResponseEntity.ok(userSignDto);
    }

    @GetMapping("/securitycontext")
    public ResponseEntity<?> confirm() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("authentcation: {}", authentication.getName());
        log.info("authentcation: {}", authentication.getAuthorities());
        log.info("authentcation: {}", authentication.getCredentials());
        log.info("authentcation: {}", authentication.getDetails());
        log.info("authentcation: {}", authentication.getPrincipal());


        return ResponseEntity.ok(authentication);
    }

    @GetMapping("/login/google")
    public void addEmail(HttpServletResponse response) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.isAuthenticated() && authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient("google", authentication.getName());
            log.info("로그인 구글의 {}", authorizedClient);
            if (authorizedClient != null) {
                response.sendRedirect(GOOGLE_LOGIN_FORM);
            }
            return;
        }
        response.sendRedirect(GOOGLE_LOGIN_FORM);
    }

    @GetMapping("/add/google2")
    public void addGoogle2(@RequestParam("nickname") String nickname, HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal UserDetails userDetails) throws IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        log.info("add/google 의 userDetails: {}", userDetails);

        if (authentication == null) {
            throw new InvalidObjectException("유저객체 없음.");
        }

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            tokenStore.storeToken(nickname, token);
            log.info("Token stored for user {}", nickname);
        } else {
            log.warn("Bearer token not found in request");
        }

        response.sendRedirect(GOOGLE_LOGIN_FORM);
    }

    @PostMapping("/add/google")
    public void addGoogle(@RequestBody Map<String, String> body, HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal UserDetails userDetails) throws IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String nickname = body.get("nickname");

        log.info("add/google 의 userDetails: {}", userDetails);

        if (authentication == null) {
            throw new InvalidObjectException("유저객체 없음.");
        }

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            tokenStore.storeToken(nickname, token);
            log.info("Token stored for user {}", nickname);
        } else {
            log.warn("Bearer token not found in request");
        }

        response.sendRedirect(GOOGLE_LOGIN_FORM);
    }


    @GetMapping("/login/google/success")
    public void OAuth2loginSuccess(OAuth2AuthenticationToken authentication, HttpServletResponse response) throws Exception {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());


        if (client == null) {
            throw new IllegalStateException("클라이언트 정보를 찾을 수 없습니다.");
        }

        GoogleTokenDto findDTO = googleTokenRepository.findByClient(authentication.getName()).orElse(null);
        Email findEmail = emailRepository.findBySocialId(findDTO.getClient()).orElse(null);
        User findUser = findEmail.getUser();
        if (findUser == null) {
            throw new Exception();
        }

        String redirectUrl = "/success" +
                String.format("?access_token=%s&email=%s",
                        URLEncoder.encode(findUser.getAccessToken(), StandardCharsets.UTF_8),
                        URLEncoder.encode(authentication.getPrincipal().getAttributes().get("email").toString(), StandardCharsets.UTF_8));

        log.info("redirectUrl = {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

//
//        HttpHeaders headers = new HttpHeaders();
//        headers.add("Authorization", findUser.getAccessToken());
//        log.info("로그인 구글 석세스 헤더 설정: {}", findUser.getAccessToken());
//        HashMap<Object, Object> responseBody = new HashMap<>();
//        responseBody.put("email", authentication.getPrincipal().getAttributes().get("email").toString());



    @PostMapping("/login")
    public ResponseEntity<User> login(LoginForm loginForm) throws Exception {
        User loginUser = userService.login(loginForm);
        return ResponseEntity.ok(loginUser);

    }

}
