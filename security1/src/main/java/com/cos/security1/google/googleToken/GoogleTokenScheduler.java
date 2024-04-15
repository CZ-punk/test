package com.cos.security1.google.googleToken;

import com.cos.security1.domain.mail.Mail;
import com.cos.security1.domain.mail.MailRepository;
import com.cos.security1.google.GmailService;
import com.google.api.client.json.Json;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePartHeader;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;


@Component
@Slf4j
@RequiredArgsConstructor
public class GoogleTokenScheduler {

    private final GoogleTokenRepository googleTokenRepository;
    private final MailRepository mailRepository;
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
            if (!token.isTokenExpired()) {
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

    @Scheduled(fixedDelay = 100000000)
    public void UpdateMailDB() {


        log.info("Mail DB Update start");
        List<GoogleTokenDto> allTokens = googleTokenRepository.findAll();

        for (GoogleTokenDto token : allTokens) {
            try {
                log.info("update Mail DB: {}", token);
                Gmail gmailService = GmailService.getGmailService(token.getAccessToken());
                String userId = "me";

                //List<Message> messages =
                gmailService.users().messages().list(userId)
                        .setLabelIds(Collections.singletonList("INBOX"))
                        .setQ("-category:promotions -category:social").execute().getMessages()
                        .parallelStream().forEach(message -> {

                            Message msg = null;
                            try {
                                msg = gmailService.users().messages().get(userId, message.getId()).setFormat("full").execute();
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }

                            String subject = null, from = null, date = null;
                            List<MessagePartHeader> headers = msg.getPayload().getHeaders();
                            for (MessagePartHeader header : headers) {
                                switch (header.getName()) {
                                    case "Subject":
                                        subject = header.getValue();
                                        break;
                                    case "From":
                                        from = header.getValue();
                                        break;
                                    case "Date":
                                        date = header.getValue();
                                        break;
                                }
                            }

                            boolean exists = mailRepository.existsByMessageId(msg.getId());
                            if (!exists) {
                                Mail mail = Mail.builder()
                                        .messageId(msg.getId())
                                        .mailFrom(from)
                                        .receiveTime(date)
                                        .contents(msg.getSnippet())
                                        .googleTokenDto(token)
                                        .subject(subject)
                                        .build();
                                mailRepository.save(mail);
                            }

                        });
                }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        log.info("Mail DB Update End");
    }
}
