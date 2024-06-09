package com.cos.security1.summary;

import com.cos.security1.domain.user.entity.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class SummarySetting {

    @Id @GeneratedValue
    @Column(name = "SETTING_ID")
    private Long id;
    private Boolean summaryOnOff = true;
    private Integer summaryLength = 30;
    private String speech = "구어체";

    public SummarySetting() {
    }

    public SummarySetting(Boolean summaryOnOff, Integer summaryLength, String speech) {
        this.summaryOnOff = summaryOnOff;
        this.summaryLength = summaryLength;
        this.speech = speech;
    }

    @OneToOne(fetch = FetchType.LAZY)
    @JsonIgnore
    private User user;
}
