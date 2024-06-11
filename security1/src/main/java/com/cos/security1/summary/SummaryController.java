package com.cos.security1.summary;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.mail.Mail;
import com.cos.security1.domain.mail.MailRepository;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import com.cos.security1.google.googleToken.GoogleTokenRepository;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.EntityManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
public class SummaryController {

    private final SummaryService summaryService;
    private final MailRepository mailRepository;
    private final UserRepository userRepository;
    private final GoogleTokenRepository googleTokenRepository;
    private final EntityManager em;

    @PostMapping("/api/setting")
    @Transactional
    public ResponseEntity<?> setting(HttpServletRequest request, @RequestBody SettingInfo settingInfo) {

        log.info("/setting {}  , {}", settingInfo.getLength(), settingInfo.getSpeech());
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }

        User findUser = userRepository.findByAccessToken(token).orElse(null);
        if (findUser == null) {
            throw new IllegalStateException("findUser == null");
        }

        SummarySetting setting = findUser.getSetting();
        setting.setSpeech(settingInfo.getSpeech());
        setting.setSummaryLength(settingInfo.getLength());
        findUser.changeSetting(setting);
        em.persist(setting);
        em.flush();

        return ResponseEntity.ok(settingInfo);
    }



    @PostMapping("/summarize")
    public ResponseEntity<?> summarize(HttpServletRequest request, @RequestBody SummaryInfo summaryInfo) throws Exception {

        log.info("/summarize {}", summaryInfo.getMessageId());
        List resultList = em.createQuery("select m from Mail m where messageId = :messageId")
                .setParameter("messageId", summaryInfo.getMessageId())
                .getResultList();

        Mail findMail = (Mail) resultList.getFirst();

        if (findMail == null) {
            throw new Exception("findMail.isEmpty");
        }

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            log.info("해당 request 의 Authorization 헤더에서 accessToken 을 찾을 수 없습니다: {}", token);
        }

        User findUser = userRepository.findByAccessToken(token).orElse(null);

        if (findUser == null) {
            throw new IllegalStateException("findUser == null");
        }

        log.info("SummaryInfo: {}", summaryInfo);
        ServerSendDto sendDto = ServerSendDto.builder()
                .subject(findMail.getSubject())
                .contents(findMail.getContents())
                .speech(findUser.getSetting().getSpeech())
                .length(findUser.getSetting().getSummaryLength())
                .build();
        ServerReceiveDto receiveDto = summaryService.getSummaryFromAiServer(sendDto);
        log.info("sendDto: {}", sendDto);
        log.info("receiveDto: {}", receiveDto);

        return ResponseEntity.ok(receiveDto);
    }
}
