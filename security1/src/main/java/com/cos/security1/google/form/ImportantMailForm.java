package com.cos.security1.google.form;

import lombok.Data;

@Data
public class ImportantMailForm {

    private String messageId;
    private String sender;
    private String receiver;
    private String subject;
    private String snippet;

    public ImportantMailForm(String messageId, String sender, String receiver, String subject, String snippet) {
        this.messageId = messageId;
        this.sender = sender;
        this.receiver = receiver;
        this.subject = subject;
        this.snippet = snippet;
    }
}
