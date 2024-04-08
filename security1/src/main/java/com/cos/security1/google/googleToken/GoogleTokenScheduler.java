package com.cos.security1.google.googleToken;

import com.google.api.client.json.Json;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;


@Component
@Slf4j
@RequiredArgsConstructor
public class GoogleTokenScheduler {

    private final GoogleTokenRepository googleTokenRepository;
    private RestTemplate restTemplate = new RestTemplate();

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String CLIENT_ID;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String CLIENT_SECRET;
    private static final String GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
    @Scheduled(fixedDelay = 1500000) //
    public void refreshTokenTask() {
        Iterable<GoogleTokenDto> tokenList = googleTokenRepository.findAll();

        for (GoogleTokenDto token : tokenList) {
            if (token.isTokenExpired()) {
                log.info("Token for client {} is expired. Refreshing...", token.getClient());

                JSONObject requestJson = new JSONObject();
                requestJson.put("client_id", CLIENT_ID);
                requestJson.put("client_secret", CLIENT_SECRET);
                requestJson.put("refresh_token", token.getRefreshToken());
                requestJson.put("grant_type", "refresh_token");

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);

                HttpEntity<String> entity = new HttpEntity<>(requestJson.toString(), headers);

                ResponseEntity<Map> response = restTemplate.postForEntity(GOOGLE_TOKEN_ENDPOINT, entity, Map.class);

                if (response.getStatusCode() == HttpStatus.OK) {

                    String accessToken = response.getBody().get("access_token").toString();
                    Long expiresIn = Long.parseLong(response.getBody().get("expires_in").toString());
                    Long expiresAtMills = System.currentTimeMillis() + ( expiresIn * 1000L );

                    token.setAccessToken(accessToken);
                    token.setTokenExpiresAt(expiresAtMills);

                    // 여기서 JSON 응답을 파싱해서 새 access token과 refresh token을 추출하고, DB에 저장해야 합니다.
                    // 실제 구현에서는 JSON 파싱 로직을 추가해야 합니다.
                    // 예: token.setAccessToken(newAccessToken); token.setRefreshToken(newRefreshToken);
                    googleTokenRepository.save(token);
                }
                else {
                    log.info("시발 재발급 오류났걸랑요....");
                }
            }
        }
    }

}
