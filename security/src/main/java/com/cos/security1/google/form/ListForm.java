package com.cos.security1.google.form;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class ListForm {

    private String id;
    private String from;
    private String subject;
    private LocalDateTime receivedTime;

    public ListForm(String id, String from, String subject, LocalDateTime receivedTime) {
        this.id = id;
        this.from = from;
        this.subject = subject;
        this.receivedTime = receivedTime;
    }
}
