package com.cos.security1.google.form;

import lombok.Data;

@Data
public class SpamForm {

    private String id;
    private String subject;
    private String snippet;

    public SpamForm(String id, String subject, String snippet) {
        this.id = id;
        this.subject = subject;
        this.snippet = snippet;
    }
}
