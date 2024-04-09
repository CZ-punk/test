package com.cos.security1.jwt.handler;

import com.cos.security1.jwt.JwtService;
import com.cos.security1.domain.user.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Value("${jwt.access.expiration}")
    private String accessTokenExpiration;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String email = extractUsername(authentication);
        String accessToken = jwtService.createAccessToken(email);
        String refreshToken = jwtService.createRefreshToken(email);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);



        log.info("login Success Handler authentication: {}", authentication);
//        SecurityContextHolder.getContext().setAuthentication(authentication);

        userRepository.findByEmail(email)
                .ifPresent(user -> {
                    user.updateRefreshToken(refreshToken);
                    userRepository.saveAndFlush(user);
                });
        log.info("로그인에 성공하였습니다. 이메일: {}", email);
        log.info("로그인에 성공하였습니다. AccessToken: {}", accessToken);
        log.info("로그인에 성공하였습니다. Expiration: {}", accessTokenExpiration);
        
        log.info("Authentication saved to SecurityContext in thread: " + Thread.currentThread().getName());
    }

    private String extractUsername(Authentication authentication) {
        log.info("login Success Authentication: {}", authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        log.info("principal: {}", userDetails);

        return userDetails.getUsername();
    }
}
