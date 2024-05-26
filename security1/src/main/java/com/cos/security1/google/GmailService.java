package com.cos.security1.google;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.mail.Mail;
import com.cos.security1.domain.mail.MailRepository;
import com.cos.security1.domain.user.entity.Role;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.google.form.ListForm;
import com.cos.security1.google.form.SpamForm;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import com.cos.security1.google.googleToken.GoogleTokenRepository;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePartHeader;
import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.*;
import jakarta.mail.util.ByteArrayDataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.swing.text.html.Option;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class GmailService {

    private final String userId = "me";
    private final MailRepository mailRepository;
    private final GoogleTokenRepository googleTokenRepository;
    private final EmailRepository emailRepository;

    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

    public static Gmail getGmailService(String accessToken) throws IOException {
        Credential credential = new GoogleCredential().setAccessToken(accessToken);
        return new Gmail.Builder(new NetHttpTransport(), JSON_FACTORY, credential)
                .setApplicationName("summail")
                .build();
    }

    public List<SpamForm> fetchSpamEmailDetails(List<String> spamIds, String accessToken) throws IOException {
        Gmail gmail = getGmailService(accessToken);
        List<SpamForm> emails = new ArrayList<>();

        for (String id : spamIds) {
            Message message = gmail.users().messages().get(userId, id).execute();

            String subject = null;
            String snippet = message.getSnippet(); // 메일의 간략한 내용
            List<MessagePartHeader> headers = message.getPayload().getHeaders();
            for (MessagePartHeader header : headers) {
                if (header.getName().equals("Subject")) {
                    subject = header.getValue();
                    break;
                }
            }
            emails.add(new SpamForm(id, subject, snippet));
        }
        return emails;
    }

    public List<Message> getSpamMails(String accessToken) throws IOException {
        Gmail gmail = getGmailService(accessToken);
        String query = "label:spam";

        ListMessagesResponse response = gmail.users().messages().list(userId)
                .setQ(query)
                .setFields("messages(id,threadId), nextPageToken")
                .execute();
        return response.getMessages();
    }


    public Message sendEmail(String accessToken, String to, String from, String subject, String bodyText, MultipartFile attachment) throws IOException, MessagingException {
        Gmail gmailService = getGmailService(accessToken);

        MimeMessage email = createEmail(to, from, subject, bodyText, attachment);

        Message message = createMessageWithEmail(email);

        message = gmailService.users().messages().send(userId, message).execute();
        log.info("MessageId:\n{}", message.getId());
        log.info("message.toPrettyString():\n{}", message.toPrettyString());

        return message;
    }

    public static MimeMessage createEmail(String to, String from, String subject, String bodyText, MultipartFile attachment) throws MessagingException, IOException {
        Properties props = new Properties();
        Session session = Session.getDefaultInstance(props, null);


        MimeMessage email = new MimeMessage(session);
        email.setFrom(new InternetAddress(from));
        email.addRecipient(jakarta.mail.Message.RecipientType.TO, new InternetAddress(to));
        email.setSubject(subject);

        MimeMultipart multipart = new MimeMultipart();
        MimeBodyPart textPart = new MimeBodyPart();

        textPart.setText(bodyText, "utf-8");
        multipart.addBodyPart(textPart);
        if (attachment != null && !attachment.isEmpty()) {
            MimeBodyPart attachmentPart = new MimeBodyPart();

            DataSource dataSource = new ByteArrayDataSource(attachment.getInputStream(), attachment.getContentType());
            attachmentPart.setDataHandler(new DataHandler(dataSource));
            attachmentPart.setFileName(attachment.getOriginalFilename());
            multipart.addBodyPart(attachmentPart);
        }
        email.setContent(multipart);

        return email;
    }

    // MimeMessage 를 gmail api 의 Message 로 형태로 변환하는 코드
    public static Message createMessageWithEmail(MimeMessage email) throws MessagingException, IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        email.writeTo(buffer);
        byte[] bytes = buffer.toByteArray();
        String encodedEmail = Base64.getUrlEncoder().encodeToString(bytes);
        Message message = new Message();
        message.setRaw(encodedEmail);
        return message;
    }

    // 소셜로그인하면 딱 한번만 호출
    @Transactional
    public void addDBMail(String accessToken) throws IOException {
        Gmail gmail = getGmailService(accessToken);


        Optional<GoogleTokenDto> findToken = googleTokenRepository.findByAccessToken(accessToken);
        Optional<Email> findEmail = emailRepository.findBySocialId(findToken.get().getClient());
        List<Mail> tokenMailList = findToken.get().getMail();
        List<Mail> emailMailList = findEmail.get().getMail();
        gmail.users().messages().list(userId).setLabelIds(List.of("INBOX"))
                .setQ("-category:promotions -category:social").execute()
                .getMessages().parallelStream().forEach(message -> {

                    Message msg = null;
                    try {
                        msg = gmail.users().messages().get(userId, message.getId()).setFormat("full").execute();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    String subject = null;
                    String from = null;
                    String date = null;

                    List<MessagePartHeader> headers = msg.getPayload().getHeaders();
                    for (MessagePartHeader header : headers) {
                        if ("Subject".equals(header.getName())) {
                            subject = header.getValue();
                        }
                        if ("From".equals(header.getName())) {
                            from = header.getValue();
                        }
                        if ("Date".equals(header.getName())) {
                            date = header.getValue();
                        }
                    }


                    Mail mail = Mail.builder()
                            .messageId(msg.getId())
                            .mailFrom(from)
                            .receiveTime(date)
                            .contents(msg.getSnippet())
                            .googleTokenDto(findToken.get())
                            .email(findEmail.get())
                            .subject(subject)
                            .build();

                    mailRepository.save(mail);

                    tokenMailList.add(mail);
                    emailMailList.add(mail);
                    log.info("\n\n");
                });
    }


    /**
     * PayLoad 확인용 메서드
     */
    public List<Message> confirmProject(String accessToken) throws IOException {

        Gmail gmail = getGmailService(accessToken);

        ListMessagesResponse response = gmail.users().messages().list(userId).setLabelIds(List.of("INBOX"))
                .setQ("-category:promotions -category:social").execute();

        List<Message> messageInfo = Collections.synchronizedList(new ArrayList<>());
        response.getMessages().parallelStream().forEach(message -> {

            Message msg = null;
            try {
                msg = gmail.users().messages().get(userId, message.getId()).setFormat("full").execute();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            messageInfo.add(msg);

        });
        return messageInfo;
    }


    /**
     *  메일 리스트 중 해당 메일을 클릭했을 때 고유의 ID 와 매핑하여 contents 정보를 보여주자.

     *  그냥 ID 값 보내주면 내가 컨텐츠만 보여주는 걸로 하자. ( 그전에 어차피 다 보냄, 송신자나 시간정보 등등 )
     *  고유한 ID 의 메시지 정보를 full 로 가져오는 함수
     *
     */

    public Message getMailById(String accessToken, String messageId) throws IOException {

        Gmail gmail = getGmailService(accessToken);
        Message message = gmail.users().messages().get(userId, messageId).setFormat("full").execute();
        return message;
    }



    public List<ListForm> fetchInboxBasicMessage(String accessToken) throws IOException {

        Gmail gmail = getGmailService(accessToken);

        // Inbox label 가진 메시지들 조회
        ListMessagesResponse response = gmail.users().messages().list(userId)
                .setLabelIds(List.of("INBOX"))
                .setQ("-category:promotions -category:social")
                .setFields("messages(id,threadId), nextPageToken")
                .execute();

        List<ListForm> filteredMessage = Collections.synchronizedList(new ArrayList<>());
        response.getMessages().parallelStream().forEach(message -> {

            try {
                Message msgDetail = gmail.users().messages().get(userId, message.getId())
                        .setFormat("metadata")
                        .setFields("id, payload(headers), internalDate")
                        .execute();

                String from = "";
                String subject = "";
                LocalDateTime receivedTime = null;

                for(var header : msgDetail.getPayload().getHeaders()) {

                    if (header.getName().equals("From")) {
                        from = header.getValue();
                    } else if (header.getName().equals("Subject")) {
                        subject = header.getValue();
                    } else if (header.getName().equals("Date")) {
                        receivedTime = Instant.ofEpochMilli(msgDetail.getInternalDate()).atZone(ZoneId.systemDefault()).toLocalDateTime();
                    }
                }

                filteredMessage.add(new ListForm(message.getId(), from, subject, receivedTime));
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }

        });

        return filteredMessage;
    }


    /**
     *
     *    public Message sendReplyEmail(String accessToken, String to, String from, String subject, String bodyText, String inReplyTo, String references) throws MessagingException, IOException {
     *         Gmail gmailService = getGmailService(accessToken);
     *
     *         MimeMessage email = new MimeMessage(Session.getDefaultInstance(new Properties(), null));
     *         email.setFrom(new InternetAddress(from));
     *         email.addRecipient(jakarta.mail.Message.RecipientType.TO, new InternetAddress(to));
     *         email.setSubject(subject);
     *         email.setText(bodyText);
     *
     *         log.info("in-reply-to: {}", inReplyTo);
     *         log.info("References: {}", references);
     *
     *         // 원본 메일의 Message-ID를 참조하는 헤더 설정, 구글서버에서 해당 정보를 통해 이전 답장들과 함께 정보 처리
     *         email.setHeader("In-Reply-To", inReplyTo);
     *         email.setHeader("References", references);
     *
     *
     *         Message message = createMessageWithEmail(email);
     *         message = gmailService.users().messages().send(userId, message).execute();
     *         return message;
     *     }
     *
     */




}
