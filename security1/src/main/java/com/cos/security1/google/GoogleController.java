package com.cos.security1.google;

import com.cos.security1.domain.mail.MailRepository;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.google.form.ListForm;
import com.cos.security1.oauth2.CustomOAuth2User;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.result.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.List;

@Controller
@Slf4j
@RequiredArgsConstructor
public class GoogleController {

    private final GmailService gmailService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private static final String GOOGLE = "google";

    /**
     *  프론트에서는 직접 토큰값을 넘겨주기 때문에 이것을 PathVariable 또는헤더로 받자
     */

    /**
     * ex inbox
     */

//    @GetMapping("/box")
//    public ListMessagesResponse exBox(@AuthenticationPrincipal CustomOAuth2User oAuth2User) throws IOException {
//
//        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, oAuth2User.getName());
//        Gmail googleClient = GmailService.getGmailService(client.getAccessToken().getTokenValue());
//
//        return gmailService.listMessages(googleClient, "me");
//
//
//    }


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





}
