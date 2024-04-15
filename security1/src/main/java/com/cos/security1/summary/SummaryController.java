package com.cos.security1.summary;

import com.cos.security1.domain.mail.Mail;
import com.cos.security1.domain.mail.MailRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class SummaryController {

    private final SummaryService summaryService;
    private final MailRepository mailRepository;

    @PostMapping("/summarize")
    public ResponseEntity<?> summarize(@RequestBody SummaryInfo summaryInfo) throws Exception {

        Mail findMail = mailRepository.findByMessageId(summaryInfo.getMessageId()).orElse(null);
        if (findMail == null) {
            throw new Exception("findMail.isEmpty");
        }

        ServerSendDto sendDto = ServerSendDto.builder()
                .subject(findMail.getSubject())
                .contents(findMail.getContents())
                .speech(summaryInfo.getSpeech())
                .length(summaryInfo.getLength())
                .build();



        ServerReceiveDto receiveDto = summaryService.getSummaryFromAiServer(sendDto);
        findMail.addSummaryContents(receiveDto.getSummary());

        log.info("sendDto: {}", sendDto);
        log.info("receiveDto: {}", receiveDto);

        return ResponseEntity.ok(receiveDto);
    }

}
