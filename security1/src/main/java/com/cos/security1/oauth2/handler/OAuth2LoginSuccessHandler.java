package com.cos.security1.oauth2.handler;

import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.jwt.JwtService;
import com.cos.security1.oauth2.CustomOAuth2User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final EmailRepository emailRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

            // get Email 을 통해 어떤 레포지토리에 있는 지 확인 후 넣자.
            log.info("get Class? {}",oAuth2User.getEmail());

            if (userRepository.findByEmail(oAuth2User.getEmail()).isPresent()) {
                loginSuccess(response, oAuth2User);
            }

            if (emailRepository.findByEmail(oAuth2User.getEmail()).isPresent()) {
                addSuccess(response, oAuth2User);
            }

            response.sendRedirect("/");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // TODO : 소셜 로그인 시에도 무조건 토큰 생성하지 말고 JWT 인증 필터처럼 RefreshToken 유/무에 따라 다르게 처리
    private void loginSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User) {

        log.info("OAuth2 Login Success !");

        String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
        String refreshToken = jwtService.createRefreshToken();
        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);
        response.addHeader(jwtService.getRefreshHeader(), "Bearer " + refreshToken);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        jwtService.updateUserRefreshToken(oAuth2User.getEmail(), refreshToken);

    }

    private void addSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User) {

        log.info("OAuth2 Add Success !");

        String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
        String refreshToken = jwtService.createRefreshToken();
        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);
        response.addHeader(jwtService.getRefreshHeader(), "Bearer " + refreshToken);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        jwtService.updateEmailRefreshToken(oAuth2User.getEmail(), refreshToken);
    }

}
