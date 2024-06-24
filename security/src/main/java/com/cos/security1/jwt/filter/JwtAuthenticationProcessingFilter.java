package com.cos.security1.jwt.filter;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.jwt.JwtService;
import com.cos.security1.jwt.util.PasswordUtil;
import com.cos.security1.domain.user.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.HeaderUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private static final String NO_CHECK_URL = "/login"; // "/login"으로 들어오는 요청은 Filter 작동 X
    private static final String SIGN_UP = "/sign-up";


    private final JwtService jwtService;
    private final UserRepository userRepository;


    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        log.info("doFilterInternal: authentication: {}", SecurityContextHolder.getContext().getAuthentication());
        log.info("what does request? {}", request.getRequestURI());

        if (isOAuth2AuthenticationRequest(request)) {
            filterChain.doFilter(request, response);
            log.info("isOAuth2AuthenticationRequest 지나갑니다~~");
            return;
        }

        if (isPermittedRequest(request)) {
            filterChain.doFilter(request, response); // "/login" 요청이 들어오면, 다음 필터 호출
            log.info("isPermittedRequest 지나갑니다~~");
            return; // return으로 이후 현재 필터 진행 막기 (안해주면 아래로 내려가서 계속 필터 진행시킴)
        }

        String accessToken = jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .orElse(null);

        if (accessToken != null) {
            log.info("token 이 null 이 아니야~~");
            checkAccessTokenAndAuthentication(request, response, filterChain);
            return;
        }

        /**
         *
         * access TOken 이 null 이면
         */

        if (accessToken == null) {
            try {
                String token = jwtService.extractAccessToken(request).orElse(null);
                log.info("what does request? {}", request.getRequestURI());
                if (token == null) {
                    // exception 처리 해당 토큰은 유효하지 않다고 오류 제공하고 리턴
                    throw new InvalidObjectException("토큰이 없거나 내가 만든 토큰이 아니에요.");
                }

                Optional<String> emailClaim = jwtService.getEmailClaim(token);
                Optional<User> user = userRepository.findByEmail(emailClaim.get());
                String refreshToken = user.get().getRefreshToken();

                // user 가 가지고 있는 리프레쉬 토큰이 유효하다면..
                if (jwtService.isTokenValid(refreshToken)) {
                    
                    String reIssuedRefreshToken = reIssueRefreshToken(user.get());  // 재발급
                    jwtService.sendAccessAndRefreshToken(response, jwtService.createAccessToken(user.get().getEmail()), reIssuedRefreshToken);
                    filterChain.doFilter(request, response);
                    return;
                }
                
                // user 가 가지고 있는 리프레쉬 토큰이 유효하지 않다면..
                else {
                    
                }
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
    }

    private boolean isPermittedRequest (HttpServletRequest request){
        String requestURI = request.getRequestURI();
        return requestURI.equals(NO_CHECK_URL) ||
                requestURI.equals(SIGN_UP) ||
                requestURI.equals("/") ||
                requestURI.startsWith("/login/google") ||
                requestURI.isEmpty() ||
                requestURI.startsWith("/success") ||
                requestURI.startsWith("/favicon.ico") ||
                requestURI.startsWith("/logout") ||
                requestURI.startsWith("/add/google") ||
                requestURI.startsWith("/.env");
    }

    private boolean isOAuth2AuthenticationRequest (HttpServletRequest request){
        String requestURI = request.getRequestURI();
        // OAuth2 인증 요청 URL 패턴 확인
        return requestURI.startsWith("/oauth2/authorization/") || requestURI.startsWith("/login/oauth2/code/");
    }

    public void saveAuthentication(User myUser) {
        String password = myUser.getPassword();
        if (password == null) { // 소셜 로그인 유저의 비밀번호 임의로 설정 하여 소셜 로그인 유저도 인증 되도록 설정
            password = PasswordUtil.generateRandomPassword();
        }
        UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
                .username(myUser.getEmail())
                .password(password)
                .roles(myUser.getRole().name())
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetailsUser, null,
                        authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
        userRepository.findByRefreshToken(refreshToken)
                .ifPresent(user -> {
                    String reIssuedRefreshToken = reIssueRefreshToken(user);
                    jwtService.sendAccessAndRefreshToken(response, jwtService.createAccessToken(user.getEmail()),
                            reIssuedRefreshToken);
                });
    }

    private String reIssueRefreshToken(User user) {
        String reIssuedRefreshToken = jwtService.createRefreshToken(user.getEmail());
        user.updateRefreshToken(reIssuedRefreshToken);
        userRepository.saveAndFlush(user);
        return reIssuedRefreshToken;
    }

    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                  FilterChain filterChain) throws ServletException, IOException {
        log.info("checkAccessTokenAndAuthentication() 호출");
        jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(accessToken -> jwtService.extractEmail(accessToken)
                        .ifPresent(email -> userRepository.findByEmail(email)
                                .ifPresent(this::saveAuthentication)));

        filterChain.doFilter(request, response);
    }

}
    
