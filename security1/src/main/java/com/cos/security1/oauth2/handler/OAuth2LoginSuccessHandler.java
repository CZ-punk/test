package com.cos.security1.oauth2.handler;

import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import com.cos.security1.google.googleToken.GoogleTokenRepository;
import com.cos.security1.jwt.JwtService;
import com.cos.security1.oauth2.CustomOAuth2User;
import com.cos.security1.summary.SummarySetting;
import jakarta.persistence.EntityManager;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
@Transactional
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final EmailRepository emailRepository;
    private final GoogleTokenRepository googleTokenRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final EntityManager em;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        try {

            log.info("OAuth2SuccessHandler: {}", authentication);
            
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

            log.info("OAuth2 성공 핸들러: {}", request);
            log.info("OAuth2 성공 핸들러: {}", response);
            log.info("OAuth2 성공 핸들러: {}", authentication);

            log.info("{} = 이름", oAuth2User.getAttributes().get("name"));



            if (emailRepository.findByEmail(oAuth2User.getEmail()).isPresent()) {
                addSuccess(response, oAuth2User);
            }
            addGoogleTokenDTO(oAuth2User);

            if (userRepository.findByEmail(oAuth2User.getEmail()).isPresent()) {
                String redirectUrl = loginSuccess(response, oAuth2User);
                log.info("redirect Success URL: {}", redirectUrl);
                response.sendRedirect(redirectUrl);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // TODO : 소셜 로그인 시에도 무조건 토큰 생성하지 말고 JWT 인증 필터처럼 RefreshToken 유/무에 따라 다르게 처리
    private String loginSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User) throws IOException {

        log.info("OAuth2 Login Success !");

        String accessToken = null;
        String refreshToken = null;

        User byEmail = userRepository.findByEmail(oAuth2User.getEmail()).orElse(null);
        if (byEmail != null) {
            boolean tokenValid = jwtService.isTokenValid(byEmail.getAccessToken());
            if (!tokenValid) {
                log.info("fucking token not valid!");
                accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
                refreshToken = jwtService.createRefreshToken(oAuth2User.getEmail());
            } else {
                accessToken = byEmail.getAccessToken();
                refreshToken = byEmail.getRefreshToken();
            }
        }

        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);
        response.addHeader(jwtService.getRefreshHeader(), "Bearer " + refreshToken);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        jwtService.setAccessToken(oAuth2User.getEmail(), accessToken);
        jwtService.updateUserRefreshToken(oAuth2User.getEmail(), refreshToken);

        String name = (String) oAuth2User.getAttributes().get("name");
        String encodedName = URLEncoder.encode(name, StandardCharsets.UTF_8);
        System.out.println("encodedName = " + encodedName);

        if (byEmail.getSetting() == null) {
            SummarySetting setting = new SummarySetting(true, 30, "구어체");
            em.persist(setting);
            byEmail.changeSetting(setting);
        }

        return "summail://success?access_token=" + accessToken + "&email=" + oAuth2User.getEmail() + "&username=" + encodedName;

        // accessToken 값이 valid 하면 값 변경X
    }


    private void addSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User) throws IOException {

        log.info("OAuth2 Add Success !");
        log.info("OAuth2 Add Success ! {}", oAuth2User.getName());
        log.info("OAuth2 Add Success ! {}", oAuth2User.getEmail());

        String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
        String refreshToken = jwtService.createRefreshToken(oAuth2User.getEmail());
        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);
        response.addHeader(jwtService.getRefreshHeader(), "Bearer " + refreshToken);

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        jwtService.updateEmailRefreshToken(oAuth2User.getEmail(), refreshToken);


    }

    private void addGoogleTokenDTO(CustomOAuth2User oAuth2User) {

        //==========================//

        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oAuth2User, oAuth2User.getAuthorities(), "google");
        log.info("Authentication Success Handler {}", authentication);

        OAuth2AuthorizedClient client =  authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());


        GoogleTokenDto tokenDto = null;
        Optional<GoogleTokenDto> findClient = googleTokenRepository.findByClient(authentication.getName());

        if (findClient.isPresent()) {
            // 이미 존재하는 경우, 기존 객체를 업데이트
            tokenDto = findClient.get();
            tokenDto.setAccessToken(client.getAccessToken().getTokenValue());
            tokenDto.setRefreshToken(client.getRefreshToken().getTokenValue());
            tokenDto.setTokenExpiresAt(client.getAccessToken().getExpiresAt().toEpochMilli());

        } else {
            // 새로운 객체를 생성
            tokenDto = new GoogleTokenDto();
            tokenDto.setAccessToken(client.getAccessToken().getTokenValue());
            tokenDto.setRefreshToken(client.getRefreshToken().getTokenValue());
            tokenDto.setTokenExpiresAt(client.getAccessToken().getExpiresAt().toEpochMilli());
            tokenDto.setClient(authentication.getName());
        }

        googleTokenRepository.saveAndFlush(tokenDto);
    }

}
