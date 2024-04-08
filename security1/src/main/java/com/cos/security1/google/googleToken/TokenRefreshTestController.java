package com.cos.security1.google.googleToken;

import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class TokenRefreshTestController {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    private RestTemplate restTemplate = new RestTemplate();
    private static final String GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

    @GetMapping("/testRefreshToken")
    public String testRefreshToken(@RequestBody DTO dto) {
        // 여기서는 하드코딩된 리프레시 토큰을 사용합니다. 실제로는 저장소에서 가져와야 합니다.

        String refreshToken = dto.getRefreshToken();

        JSONObject requestJson = new JSONObject();
        requestJson.put("client_id", clientId);
        requestJson.put("client_secret", clientSecret);
        requestJson.put("refresh_token", refreshToken);
        requestJson.put("grant_type", "refresh_token");


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // HttpEntity를 사용하여 헤더와 JSON 본문을 함께 전송합니다.
        HttpEntity<String> entity = new HttpEntity<>(requestJson.toString(), headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                GOOGLE_TOKEN_ENDPOINT,
                entity,
                String.class);

        return response.getBody();
    }
}