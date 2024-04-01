package com.cos.security1.google;

import com.cos.security1.domain.mail.MailRepository;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.google.form.ListForm;
import com.cos.security1.oauth2.CustomOAuth2User;
import com.google.api.services.gmail.model.Message;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/api")
@RequiredArgsConstructor
public class GoogleController {

    private final UserRepository userRepository;
    private final MailRepository mailRepository;
    private final GmailService gmailService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private static final String GOOGLE = "google";

    /**
     * 확인용 메서드
     */
    @GetMapping("/confirm")
    public ResponseEntity<?> confirmPayload(@AuthenticationPrincipal CustomOAuth2User oAuth2User) throws IOException {

        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, oAuth2User.getName());
        log.info("Authenticated User name: {}", oAuth2User.getName());
        List<Message> messages = gmailService.confirmProject(client.getAccessToken().getTokenValue());
        log.info("AccessToken: {}\n", client.getAccessToken().getTokenValue());

        return ResponseEntity.ok(messages);

    }

    @GetMapping("/box")
    public ResponseEntity<List> getMailBox(@AuthenticationPrincipal CustomOAuth2User oAuth2User) throws  IOException {

        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, oAuth2User.getName());
        List<ListForm> listForm = gmailService.fetchInboxBasicMessage(client.getAccessToken().getTokenValue());
        log.info("listForm: {}", listForm);

        return ResponseEntity.ok(listForm);

    }


    // 테스트 결과 0.6초
    @GetMapping("/box/{emailId}")
    public ResponseEntity<?> getMailDetails(@PathVariable("emailId") String emailId,
                                            @AuthenticationPrincipal CustomOAuth2User customOAuth2User) throws IOException {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, customOAuth2User.getName());
        Message mailById = gmailService.getMailById(client.getAccessToken().getTokenValue(), emailId);
        return ResponseEntity.ok(mailById);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }



}
