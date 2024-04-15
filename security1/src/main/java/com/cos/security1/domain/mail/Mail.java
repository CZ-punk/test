package com.cos.security1.domain.mail;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.google.googleToken.GoogleTokenDto;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Mail {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "MAIL_ID")
    private Long id;

    private String messageId;
    private String mailFrom;
    private String subject;
    private String receiveTime;
    private String contents;
    private String summaryContents;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "EMAIL_ID", referencedColumnName = "EMAIL_ID")
    @JsonBackReference
    private Email email;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "GOOGLE_TOKEN_DTO_ID", referencedColumnName = "GOOGLE_TOKEN_DTO_ID")
    @JsonBackReference
    private GoogleTokenDto googleTokenDto;

    public void addSummaryContents(String summary) {
        summaryContents = summary;
    }

}
