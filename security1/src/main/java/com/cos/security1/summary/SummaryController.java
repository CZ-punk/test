package com.cos.security1.summary;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.mail.Mail;
import com.cos.security1.domain.mail.MailRepository;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import com.cos.security1.google.googleToken.GoogleTokenRepository;
import jakarta.persistence.EntityManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

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

    @PostMapping("/summarize")
    public ResponseEntity<?> summarize(@RequestBody SummaryInfo summaryInfo) throws Exception {

        List resultList = em.createQuery("select m from Mail m where messageId = :messageId")
                .setParameter("messageId", summaryInfo.getMessageId())
                .getResultList();

        Mail findMail = (Mail) resultList.getFirst();

        if (findMail == null) {
            throw new Exception("findMail.isEmpty");
        }



        GoogleTokenDto findGoogleToken = googleTokenRepository.findById(findMail.getGoogleTokenDto().getId()).get();
        User findUser = userRepository.findBySocialId(findGoogleToken.getClient()).get();

        log.info("SummaryInfo: {}", summaryInfo);

        ServerSendDto sendDto = ServerSendDto.builder()
                .subject(findMail.getSubject())
                .contents(findMail.getContents())
                .speech(findUser.getSetting().getSpeech())
                .length(findUser.getSetting().getSummaryLength())
                .build();

        log.info("ServerSendDto: {}", sendDto);


        ServerReceiveDto receiveDto = summaryService.getSummaryFromAiServer(sendDto);
//        findMail.addSummaryContents(receiveDto.getSummary());

        log.info("sendDto: {}", sendDto);
        log.info("receiveDto: {}", receiveDto);

        return ResponseEntity.ok(receiveDto);
    }

}
