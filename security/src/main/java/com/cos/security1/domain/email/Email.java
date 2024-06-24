package com.cos.security1.domain.email;

import com.cos.security1.domain.mail.Mail;
import com.cos.security1.domain.user.entity.Role;
import com.cos.security1.domain.user.entity.SocialType;
import com.cos.security1.domain.user.entity.User;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Builder
@AllArgsConstructor
public class Email {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "EMAIL_ID")
    private Long id;
    private String nickname;
    private String email;
    private String refreshToken;
    private Role role;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID")
    @Setter
    @JsonBackReference
    private User user;

    //, cascade = CascadeType.ALL, orphanRemoval = true
    @OneToMany(mappedBy = "email")
    @JsonManagedReference
    private List<Mail> mail;

    @Enumerated(EnumType.STRING)
    private SocialType socialType;

    private String socialId; // 로그인한 소셜 타입의 식별자 값 (일반 로그인인 경우 null)

    @PrePersist
    @PreUpdate
    public void synchronizeNickname() {
        this.nickname = user.getNickname();
    }

    public void updateRefreshToken(String updateRefreshToken) {
        this.refreshToken = updateRefreshToken;
    }
}
