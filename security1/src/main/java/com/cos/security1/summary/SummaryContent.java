package com.cos.security1.summary;

import com.cos.security1.domain.mail.Mail;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@Data
public class SummaryContent {

    @Id @GeneratedValue
    @Column(name = "SUMMARY_CONTENT_ID")
    private Long id;
    private String messageId;
    private String summaryContent;

    @OneToOne(mappedBy = "summaryContent", cascade = CascadeType.ALL)
    private Mail mail;

    public SummaryContent(String messageId, String summaryContent, Mail mail) {
        this.messageId = messageId;
        this.summaryContent = summaryContent;
        this.mail = mail;
    }
}
