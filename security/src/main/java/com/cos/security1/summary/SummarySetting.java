package com.cos.security1.summary;

import com.cos.security1.domain.user.entity.User;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

@Getter
@NoArgsConstructor
@Entity
@Builder
@Setter
@AllArgsConstructor
public class SummarySetting {

    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "SETTING_ID")
    private Long id;
    private Boolean summaryOnOff = true;
    private int summaryLength = 30;
    private String speech  = "구어체";

    @OneToOne(fetch = FetchType.LAZY)
    @JsonIgnore
    private User user;

    public SummarySetting(Boolean summaryOnOff, int summaryLength, String speech) {
        this.summaryOnOff = summaryOnOff;
        this.summaryLength = summaryLength;
        this.speech = speech;
    }
}
