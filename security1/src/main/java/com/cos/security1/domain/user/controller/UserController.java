package com.cos.security1.domain.user.controller;

import com.cos.security1.domain.user.dto.LoginForm;
import com.cos.security1.domain.user.dto.UserSignDto;
import com.cos.security1.domain.user.entity.User;
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

import java.io.IOException;
import java.io.InvalidObjectException;
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
            if (authorizedClient != null) {
                response.sendRedirect(GOOGLE_LOGIN_FORM);
            }
            log.info("뭐냐 시발 여기 왜 안 동작해? ㅋㅋ");
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



    @ResponseBody
    @GetMapping("/login/google/success")
    public ResponseEntity<?> OAuth2loginSuccess(OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        if (client == null) {
            throw new IllegalStateException("클라이언트 정보를 찾을 수 없습니다.");
        }

        String accessToken = client.getAccessToken().getTokenValue();
        String refreshToken = client.getRefreshToken() != null ? client.getRefreshToken().getTokenValue() : null;

        GoogleTokenDto tokenDto = null;
        Optional<GoogleTokenDto> findClient = googleTokenRepository.findByClient(authentication.getName());


        if (findClient.isPresent()) {
            // 이미 존재하는 경우, 기존 객체를 업데이트
            tokenDto = findClient.get();
            tokenDto.setAccessToken(accessToken);
            tokenDto.setRefreshToken(refreshToken);
            tokenDto.setTokenExpiresAt(client.getAccessToken().getExpiresAt().toEpochMilli());

        } else {
            // 새로운 객체를 생성
            tokenDto = new GoogleTokenDto();
            tokenDto.setAccessToken(accessToken);
            tokenDto.setRefreshToken(refreshToken);
            tokenDto.setTokenExpiresAt(client.getAccessToken().getExpiresAt().toEpochMilli());
            tokenDto.setClient(authentication.getName());
        }

        googleTokenRepository.save(tokenDto);
        HashMap<Object, Object> responseBody = new HashMap<>();
        responseBody.put("email", authentication.getPrincipal().getAttributes().get("email").toString());
        return ResponseEntity.ok(responseBody);
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(LoginForm loginForm) throws Exception {
        User loginUser = userService.login(loginForm);
        return ResponseEntity.ok(loginUser);

    }

}
