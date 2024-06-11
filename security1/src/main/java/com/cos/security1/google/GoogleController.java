package com.cos.security1.google;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.mail.Mail;
import com.cos.security1.domain.mail.MailRepository;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.google.form.*;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import com.cos.security1.google.googleToken.GoogleTokenRepository;
import com.cos.security1.oauth2.CustomOAuth2User;
import com.google.api.services.gmail.model.Message;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.*;

@Controller
@Slf4j
@RequiredArgsConstructor
public class GoogleController {

    private final GmailService gmailService;
    private final GoogleTokenRepository googleTokenRepository;
    private final UserRepository userRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final EmailRepository emailRepository;

    private static final String GOOGLE = "google";


    @GetMapping("/check/important")
    public void check_ImportantMail(HttpServletRequest request, @RequestBody String messageId) throws IOException {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 accessToken 에 대한 관련 계정은 존재하지 않습니다.");
        }

        log.info("Important Check messageId: {}", messageId);

        GoogleTokenDto googleToken = googleTokenRepository.findByClient(findUser.getSocialId()).get();

        gmailService.checkImportantMail(googleToken.getAccessToken(), messageId);

    }

    // important mail fetchImportantEmailDetails
    @ResponseBody
    @GetMapping("/api/important_mail")
    public List<ImportantMailForm> getImportantMail(HttpServletRequest request) throws IOException {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 accessToken 에 대한 관련 계정은 존재하지 않습니다.");
        }

        Long userId = findUser.getId();
        List<Email> emailList = emailRepository.findListByUserId(userId);
        log.info("/api/sent_mail emailList: {}", emailList);
        if (emailList.isEmpty()) {
            throw new IllegalStateException("AccessToken 의 userId 와 일치하는 Email 이 존재하지 않습니다.");
        }

        ArrayList<GoogleTokenDto> googleTokenList = new ArrayList<>();
        List<ImportantMailForm> result = new ArrayList<>();
        List<Message> messages = new ArrayList<>();
        List<String> importantIds = new ArrayList<>();

        for (Email findEmail : emailList) {
            googleTokenList.add(googleTokenRepository.findByClient(findEmail.getSocialId()).orElse(null));
        }

        for (GoogleTokenDto googleTokenDto : googleTokenList) {
            if (googleTokenDto == null) {
                log.info("해당 google 계정에 문제가 발생하였습니다. {}", googleTokenDto);
            }

            messages.addAll(gmailService.getImportantMails(googleTokenDto.getAccessToken()));
            for (Message message : messages) {
                importantIds.add(message.getId());
            }
            result.addAll(gmailService.fetchImportantEmailDetails(importantIds, googleTokenDto.getAccessToken()));
            importantIds.clear();
            messages.clear();
        }
        return result;
    }

    // sent mail
    @ResponseBody
    @GetMapping("/api/sent_mail")
    public List<SentMailForm> getSent(HttpServletRequest request) throws IOException {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 accessToken 에 대한 관련 계정은 존재하지 않습니다.");
        }

        Long userId = findUser.getId();
        List<Email> emailList = emailRepository.findListByUserId(userId);
        log.info("/api/sent_mail emailList: {}", emailList);
        if (emailList.isEmpty()) {
            throw new IllegalStateException("AccessToken 의 userId 와 일치하는 Email 이 존재하지 않습니다.");
        }

        ArrayList<GoogleTokenDto> googleTokenList = new ArrayList<>();
        List<SentMailForm> result = new ArrayList<>();
        List<Message> messages = new ArrayList<>();
        List<String> sentIds = new ArrayList<>();

        for (Email findEmail : emailList) {
            googleTokenList.add(googleTokenRepository.findByClient(findEmail.getSocialId()).orElse(null));
        }

        for (GoogleTokenDto googleTokenDto : googleTokenList) {
            if (googleTokenDto == null) {
                log.info("해당 google 계정에 문제가 발생하였습니다. {}", googleTokenDto);
            }

            messages.addAll(gmailService.getSentMails(googleTokenDto.getAccessToken()));
            for (Message message : messages) {
                sentIds.add(message.getId());
            }
            result.addAll(gmailService.fetchSentEmailDetails(sentIds, googleTokenDto.getAccessToken()));
            sentIds.clear();
            messages.clear();
        }
        return result;
    }

    // spam mail
    @ResponseBody
    @GetMapping("/api/spam_mail")
    public List<SpamForm> getSpam(HttpServletRequest request) throws IOException {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 accessToken 에 대한 관련 계정은 존재하지 않습니다.");
        }

        Long userId = findUser.getId();
        List<Email> emailList = emailRepository.findListByUserId(userId);
        log.info("/api/spam_mail emailList: {}", emailList);
        if (emailList.isEmpty()) {
            throw new IllegalStateException("AccessToken 의 userId 와 일치하는 Email 이 존재하지 않습니다.");
        }

        List<Message> messages = new ArrayList<>();
        ArrayList<String> spamIds = new ArrayList<>();
        ArrayList<GoogleTokenDto> googleTokenList = new ArrayList<>();
        List<SpamForm> result = new ArrayList<>();

        for (Email findEmail : emailList) {
            googleTokenList.add(googleTokenRepository.findByClient(findEmail.getSocialId()).orElse(null));
        }
        for (GoogleTokenDto googleTokenDto : googleTokenList) {
            if (googleTokenDto == null) {
                log.info("해당 google 계정에 문제가 발생하였습니다. {}", googleTokenDto);
            }
            messages.addAll(gmailService.getSpamMails(googleTokenDto.getAccessToken()));

            for (Message message : messages) {
                spamIds.add(message.getId());
            }
            result.addAll(gmailService.fetchSpamEmailDetails(spamIds, googleTokenDto.getAccessToken()));
            spamIds.clear();
            messages.clear();
        }
        return result;
    }

    // 새로운 메일 작성
    @ResponseBody
    @PostMapping("/api/send_mail")
    public ResponseEntity<SendForm> sendMail(@ModelAttribute SendForm sendForm) throws Exception {

        Long userId = userRepository.findByEmail(sendForm.getUser())
                .map(User::getId)
                .orElse(null);

        log.info("userId: {}", userId);

        String sender = sendForm.getSender();
        Email sendEmail = emailRepository.findByEmail(sendForm.getSender()).orElse(null);

        Long userIdByEmail = sendEmail.getUser().getId();
        log.info("userIdByEmail: {}", userIdByEmail);

        if (userId != userIdByEmail) {
            log.info("접근할 수 없는 이메일 계정입니다. 등록 후 사용해주세요.");
            throw new IOException("접근 불가 이메일, 등록 후 사용 바람.");
        }
        if (sendEmail == null) {
            log.info("등록되지 않은 이메일입니다: {}", sender);
            throw new Exception("등록되지 않은 이메일입니다.");
        }


        String accessToken = googleTokenRepository.findByClient(sendEmail.getSocialId())
                .map(GoogleTokenDto::getAccessToken)
                .orElse(null);

        if (accessToken == null || sendEmail.getEmail() == null) {
            throw new Exception("accessToken: " + accessToken + ", myEmail: " + sendEmail.getEmail());
        }

        log.info("send mail body: {}, {}, {}, {}", sendForm.getReceiver(), sendForm.getSubject(), sendForm.getContents(), sendForm.getAttachment());
        log.info("send_mail: myEmail: {}", sender);


        Message message = gmailService.sendEmail(accessToken, sendForm.getReceiver(), sender, sendForm.getSubject(), sendForm.getContents(), sendForm.getAttachment());
        return ResponseEntity.ok(sendForm);

    }

    @ResponseBody
    @GetMapping("/api/mail_list")
    public List<Mail> getMailList(HttpServletRequest request) throws IOException {


        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 user 에 대한 관련 계정은 존재하지 않습니다.");
        }

        List<Email> emailList = findUser.getEmailList();
        List<Mail> result = new ArrayList<>();
        for (Email email : emailList) {
            List<Mail> mailList = email.getMail();
            result.addAll(mailList);
        }

        return result;
    }

    @ResponseBody
    @GetMapping("/get/api/mail/db")
    public List<List<Mail>> setMailDBget(HttpServletRequest request) throws IOException {

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 accessToken 에 대한 관련 계정은 존재하지 않습니다.");
        }
        // 이 메서드 호출시 accessToken 과 관련된 User 와 연관관계에 있는 모든 Email Entity 들을 대상으로 api 호출해서 db 초기화.
        Long userId = findUser.getId();
        List<Email> emailList = emailRepository.findListByUserId(userId);
        log.info("/api/mail/db . emailList: {}",emailList);
        if (emailList.isEmpty()) {
            throw new IllegalStateException("AccessToken 의 userId 와 일치하는 Email 이 존재하지 않습니다.");
        }

        List<List<Mail>> result = new ArrayList<>();
        ArrayList<GoogleTokenDto> googleTokenList = new ArrayList<>();
        for (Email findEmail : emailList) {
            googleTokenList.add(googleTokenRepository.findByClient(findEmail.getSocialId()).orElse(null));
        }
        for (GoogleTokenDto googleTokenDto : googleTokenList) {
            if (googleTokenDto == null) {
                log.info("해당 google 계정에 문제가 발생하였습니다. {}", googleTokenDto);
            }
            gmailService.addDBMail(googleTokenDto.getAccessToken());
            result.add(googleTokenDto.getMail());
        }
        return result;
    }

    @ResponseBody
    @PostMapping("/api/mail/db")
    public List<List<Mail>> setMailDB(HttpServletRequest request) throws IOException {

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }
        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("해당 accessToken 에 대한 관련 계정은 존재하지 않습니다.");
        }
        // 이 메서드 호출시 accessToken 과 관련된 User 와 연관관계에 있는 모든 Email Entity 들을 대상으로 api 호출해서 db 초기화.
        Long userId = findUser.getId();
        List<Email> emailList = emailRepository.findListByUserId(userId);
        log.info("/api/mail/db . emailList: {}",emailList);
        if (emailList.isEmpty()) {
            throw new IllegalStateException("AccessToken 의 userId 와 일치하는 Email 이 존재하지 않습니다.");
        }

        List<List<Mail>> result = new ArrayList<>();
        ArrayList<GoogleTokenDto> googleTokenList = new ArrayList<>();
        for (Email findEmail : emailList) {
            googleTokenList.add(googleTokenRepository.findByClient(findEmail.getSocialId()).orElse(null));
        }
        for (GoogleTokenDto googleTokenDto : googleTokenList) {
            if (googleTokenDto == null) {
                log.info("해당 google 계정에 문제가 발생하였습니다. {}", googleTokenDto);
            }
            gmailService.addDBMail(googleTokenDto.getAccessToken());
            result.add(googleTokenDto.getMail());
        }
        return result;
    }


    /**
     * 확인용 메서드
     */
    @GetMapping("/confirm")
    public ResponseEntity<?> confirmPayload(String accessToken) throws IOException {


        List<Message> messages = gmailService.confirmProject(accessToken);
        return ResponseEntity.ok(messages);
    }


    // 테스트 결과 0.6초
    @GetMapping("/gmail/list/{messageId}")
    public ResponseEntity<?> getMailDetails(@PathVariable("messageId") String messageId,
                                            @AuthenticationPrincipal CustomOAuth2User customOAuth2User) throws IOException {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, customOAuth2User.getName());
        Message mailById = gmailService.getMailById(client.getAccessToken().getTokenValue(), messageId);
        return ResponseEntity.ok(mailById);
    }

    @GetMapping("/tokenInfo")
    public ResponseEntity<?> getTokenInfo(@AuthenticationPrincipal CustomOAuth2User oAuth2User) {

        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(GOOGLE, oAuth2User.getName());
        log.info("Authenticated User name: {}", oAuth2User.getName());
        log.info("Token Info: {}", client.getAccessToken().getTokenValue());
        log.info("refreshToken info: {}", client.getRefreshToken().getTokenValue());

        Instant expiresAt = client.getAccessToken().getExpiresAt();
        return ResponseEntity.ok(expiresAt + "\n");
    }

}

