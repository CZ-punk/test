//package com.cos.security1.google;
//
//import com.cos.security1.domain.email.Email;
//import com.cos.security1.domain.email.repository.EmailRepository;
//import com.cos.security1.domain.mail.Mail;
//import com.cos.security1.domain.user.entity.User;
//import com.cos.security1.domain.user.repository.UserRepository;
//import com.cos.security1.google.form.ListForm;
//import com.cos.security1.google.googleToken.GoogleTokenDto;
//import com.cos.security1.google.googleToken.GoogleTokenRepository;
//import com.cos.security1.oauth2.CustomOAuth2User;
//import com.google.api.services.gmail.model.Message;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.annotation.AuthenticationPrincipal;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
//import org.springframework.stereotype.Controller;
//import org.springframework.web.bind.annotation.*;
//import org.springframework.web.multipart.MultipartFile;
//
//import java.io.IOException;
//import java.time.Instant;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Map;
//import java.util.Optional;
//
//@Controller
//@Slf4j
//@RequiredArgsConstructor
//public class MyTestController {
//
//    private final GmailService gmailService;
//    private final GoogleTokenRepository googleTokenRepository;
//    private final UserRepository userRepository;
//    private final OAuth2AuthorizedClientService authorizedClientService;
//    private final EmailRepository emailRepository;
//
//    private static final String GOOGLE = "google";
//
//
//    // 새로운 메일 작성
//    @ResponseBody
//    @PostMapping("/api/send_mail")
//    public ResponseEntity<Message> sendMail(@RequestParam("clientId") String clientId, @RequestParam("to") String to,
//                                            @RequestParam("subject") String subject, @RequestParam("bodyText") String bodyText, @RequestParam("attachment") MultipartFile attachment) throws Exception {
//
//        String accessToken = googleTokenRepository.findByClient(clientId)
//                .map(GoogleTokenDto::getAccessToken)
//                .orElse(null);
//        String myEmail = emailRepository.findBySocialId(clientId)
//                .map(Email::getEmail)
//                .orElse(null);
//
//        if (accessToken == null || myEmail == null) {
//            throw new Exception("accessToken: " + accessToken + ", myEmail: " + myEmail);
//        }
//
//        log.info("send mail body: {}, {}, {}, {}, {}", clientId, to, subject, bodyText, attachment);
//
//        log.info("send_mail: accessToken: {}", accessToken);
//        log.info("send_mail: myEmail: {}", myEmail);
//
//
//        Message message = gmailService.sendEmail(accessToken, to, myEmail, subject, bodyText, attachment);
//        return ResponseEntity.ok(message);
//    }
//
//    @ResponseBody
//    @PostMapping("/api/mails")
//    public List<Mail> getMail(@RequestBody Map<String, String> body) {
//
//        String nickname = body.get("nickname");
//        Optional<User> findUser = userRepository.findByNickname(nickname);
//        if (findUser.isEmpty()) {
//            log.info("byClient.isEmpty: {}", findUser);
//        }
//
//        List<Email> emailList = findUser.get().getEmailList();
//
//        List<Mail> mails = new ArrayList<>();
//
//        for (Email email : emailList) {
//            List<Mail> mailList = email.getMail();
//            log.info("EmailList 의 email: {}", email);
//            mails.addAll(mailList);
//        }
//        log.info("User 의 emailList: {}", emailList);
//        log.info("EmailList 들의 MailList: {}", mails);
//
//        return mails;
//    }
//
//
//
//
//
//    /**
//     *  프론트에서는 직접 토큰값을 넘겨주기 때문에 이것을 PathVariable 또는헤더로 받자
//     */
//    @ResponseBody
//    @PostMapping("/api/mail_list")
//    public ResponseEntity<List> getMailList(@RequestBody Map<String, String> body) throws IOException {
//
//        String clientId = body.get("clientId");
//        Optional<GoogleTokenDto> byClient = googleTokenRepository.findByClient(clientId);
//        if (byClient.isEmpty()) {
//            log.info("byClient.isEmpty: {}", byClient);
//            return null;
//        }
//
//        List<ListForm> listForm = gmailService.fetchInboxBasicMessage(byClient.get().getAccessToken());
//        log.info("listForm: {}", listForm);
//
//        return ResponseEntity.ok(listForm);
//    }
//
//
//
//    @ResponseBody
//    @PostMapping("/api/mail_list/mail_detail")
//    public ResponseEntity<Message> getDetailMail(@RequestBody Map<String, String> body) throws IOException {
//
//        String clientId = body.get("clientId");
//        String messageId = body.get("messageId");
//        Optional<GoogleTokenDto> byClient = googleTokenRepository.findByClient(clientId);
//        if (byClient.isEmpty()) {
//            log.info("byClient.isEmpty: {}", byClient);
//            return null;
//        }
//
//        return ResponseEntity.ok(gmailService.getMailById(byClient.get().getAccessToken(), messageId));
//    }
//
//
//
//    @ResponseBody
//    @PostMapping("/api/mail/db")
//    public List<Mail> setMailDB(@RequestBody Map<String, String> body) throws IOException {
//
//        String clientId = body.get("clientId");
//        Optional<GoogleTokenDto> byClient = googleTokenRepository.findByClient(clientId);
//        if (byClient.isEmpty()) {
//            log.info("byClient.isEmpty: {}", byClient);
//            return null;
//        }
//
//        gmailService.addDBMail(byClient.get().getAccessToken());
//
//        return byClient.get().getMail();
//    }
//
//    /**
//     * 확인용 메서드
//     */
//    @GetMapping("/confirm")
//    public ResponseEntity<?> confirmPayload(@AuthenticationPrincipal CustomOAuth2User oAuth2User) throws IOException {
//
//        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, oAuth2User.getName());
//        log.info("Authenticated User name: {}", oAuth2User.getName());
//        List<Message> messages = gmailService.confirmProject(client.getAccessToken().getTokenValue());
//        log.info("AccessToken: {}\n", client.getAccessToken().getTokenValue());
//
//        return ResponseEntity.ok(messages);
//    }
//
//    @GetMapping("/gmail/list")
//    public ResponseEntity<List> getMailBox(@AuthenticationPrincipal CustomOAuth2User oAuth2User) throws  IOException {
//
//        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, oAuth2User.getName());
//        List<ListForm> listForm = gmailService.fetchInboxBasicMessage(client.getAccessToken().getTokenValue());
//        log.info("listForm: {}", listForm);
//        return ResponseEntity.ok(listForm);
//    }
//
//    // 테스트 결과 0.6초
//    @GetMapping("/gmail/list/{messageId}")
//    public ResponseEntity<?> getMailDetails(@PathVariable("messageId") String messageId,
//                                            @AuthenticationPrincipal CustomOAuth2User customOAuth2User) throws IOException {
//        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, customOAuth2User.getName());
//        Message mailById = gmailService.getMailById(client.getAccessToken().getTokenValue(), messageId);
//        return ResponseEntity.ok(mailById);
//    }
//
//    @GetMapping("/tokenInfo")
//    public ResponseEntity<?> getTokenInfo(@AuthenticationPrincipal CustomOAuth2User oAuth2User) {
//
//        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, oAuth2User.getName());
//        log.info("Authenticated User name: {}", oAuth2User.getName());
//        log.info("Token Info: {}", client.getAccessToken().getTokenValue());
//        log.info("refreshToken info: {}", client.getRefreshToken().getTokenValue());
//
//        Instant expiresAt = client.getAccessToken().getExpiresAt();
//        return ResponseEntity.ok(expiresAt + "\n");
//    }
//
//}
