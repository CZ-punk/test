package com.cos.security1.google;

import com.cos.security1.google.form.ListForm;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class GmailService {

    private final String userId = "me";

    public static Gmail initializeGmailService(String accessToken) throws IOException {
        GoogleCredential credential = new GoogleCredential().setAccessToken(accessToken);
        return new Gmail.Builder(new NetHttpTransport(), JacksonFactory.getDefaultInstance(), credential)
                .setApplicationName("Your Application Name")
                .build();
    }

    /**
     * PayLoad 확인용 메서드
     */
    public List<Message> confirmProject(String accessToken) throws IOException {

        Gmail gmail = initializeGmailService(accessToken);

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

        Gmail gmail = initializeGmailService(accessToken);
        Message message = gmail.users().messages().get(userId, messageId).setFormat("full").execute();
        return message;
    }

    public List<ListForm> fetchInboxBasicMessage(String accessToken) throws IOException {

        Gmail gmail = initializeGmailService(accessToken);

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






}
