package com.cos.security1.google.form;

import lombok.Getter;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class SendForm {
    private String user;
    private String sender;
    private String receiver;
    private String subject;
    private String contents;
    private MultipartFile attachment;

    public SendForm(String user, String sender, String receiver, String subject, String contents, MultipartFile attachment) {
        this.user = user;
        this.sender = sender;
        this.receiver = receiver;
        this.subject = subject;
        this.contents = contents;
        this.attachment = attachment;
    }

}
