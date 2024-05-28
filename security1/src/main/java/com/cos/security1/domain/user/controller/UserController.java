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
import com.cos.security1.jwt.InMemoryAccountStore;
import com.cos.security1.jwt.JwtService;
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
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final GoogleTokenRepository googleTokenRepository;
    private final InMemoryAccountStore loginAccount;
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

    @GetMapping("/add/google")
    public void addGoogle(HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal UserDetails userDetails) throws IOException {


        log.info("add/google 의 userDetails: {}", userDetails);
        log.info("add/google 의 request header token: {}", request.getHeader("Authorization"));

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 accessToken 에 대한 관련 계정은 존재하지 않습니다.");
        }
        this.loginAccount.store(findUser.getId(), findUser.getEmail());
        log.info("User.getId() as Key: " + findUser.getId() + "LoginAccount as Value: " + findUser.getEmail());
        response.setHeader("Location", "ec2-13-125-246-135.ap-northeast-2.compute.amazonaws.com"+ GOOGLE_LOGIN_FORM);
    }

//    @GetMapping("/add/google2")
//    public void addGoogle2(HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal UserDetails userDetails) throws IOException {
//
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//        log.info("add/google 의 userDetails: {}", userDetails);
//        if (authentication == null) {
//            throw new InvalidObjectException("유저객체 없음.");
//        }
//
//        String loginAccount = null;
//        String token = request.getHeader("Authorization");
//        if (token != null && token.startsWith("Bearer ")) {
//            token = token.substring(7);
//        } else {
//            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
//        }
//
//        User findUser = userRepository.findByAccessToken(token).orElse(null);
//        if (findUser == null) {
//            throw new IllegalStateException("해당 계정은 존재하지 않습니다. loginAccount: " + loginAccount);
//        }
//        loginAccount = findUser.getEmail();
//        Long findId = findUser.getId();
//        this.loginAccount.store(findId, loginAccount);
//        log.info("User.getId() as Key: " + findId + ", LoginAccount as Value: " + loginAccount);
//        response.sendRedirect(GOOGLE_LOGIN_FORM);
//    }




    @GetMapping("/login/google/success")
    public void OAuth2loginSuccess(OAuth2AuthenticationToken authentication, HttpServletResponse response) throws Exception {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        log.info("/success url client: {}", client);

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
        response.setStatus(HttpServletResponse.SC_OK);
        response.sendRedirect(redirectUrl);
    }

    @GetMapping("/success")
    public String success(Model model, @RequestParam("access_token") String accessToken, @RequestParam("email") String email, HttpServletResponse response) throws IOException {
        System.out.println(accessToken);
        System.out.println(email);
        String redirectUrl = "summail://success?" +
                "access_token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8) +
                "&email=" + URLEncoder.encode(email, StandardCharsets.UTF_8);
        model.addAttribute("redirectUrl", redirectUrl);
        return "web/intercept";

    }

    @GetMapping("/fail/google")
    public void fail(HttpServletResponse response) throws IOException {
        response.getWriter().write("Social Login Fail ! Confirm Server Log..");
    }


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

    @ResponseBody
    @GetMapping("/logout/success")
    public String logout() {
        // 로그아웃 후 처리 로직 작성
        return "Success Logout!";

    }
}
