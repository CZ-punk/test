package com.cos.security1.domain.mail;

import com.cos.security1.domain.email.Email;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
public class Mail {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "MAIL_ID")
    private Long id;
    private String sender;
    private String senderAddress;
    private String receiver;
    private String title;
    private String contents;
    private String mediaFileURL;
    private String summaryContents;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "EMAIL_ID")
    private Email email;

    @Builder
    public Mail(String sender, String senderAddress, String receiver, String title, String contents, String mediaFileURL, Email email) {
        this.sender = sender;
        this.senderAddress = senderAddress;
        this.receiver = receiver;
        this.title = title;
        this.contents = contents;
        this.mediaFileURL = mediaFileURL;
        this.email = email;
    }

    public Mail() {

    }

    public void setSummaryContent(String summary) {
        this.summaryContents = summary;
    }
}
