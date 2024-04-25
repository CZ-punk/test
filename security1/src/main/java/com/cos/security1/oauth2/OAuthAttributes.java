package com.cos.security1.oauth2;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.oauth2.info.GoogleOAuth2UserInfo;
import com.cos.security1.oauth2.info.NaverOAuth2UserInfo;
import com.cos.security1.oauth2.info.OAuth2UserInfo;
import com.cos.security1.domain.user.entity.Role;
import com.cos.security1.domain.user.entity.SocialType;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.Optional;

@Getter
@Slf4j
public class OAuthAttributes {

    private String nameAttributeKey;
    private OAuth2UserInfo oAuth2UserInfo;


    @Builder
    private OAuthAttributes(String nameAttributeKey, OAuth2UserInfo oAuth2UserInfo) {
        this.nameAttributeKey = nameAttributeKey;
        this.oAuth2UserInfo = oAuth2UserInfo;
        log.info("nameAttributeKey: {}\n oAuth2UserInfo: {}", nameAttributeKey, oAuth2UserInfo);
    }

    public static OAuthAttributes of(SocialType socialType, String userNameAttributeName, Map<String, Object> attributes) {
        if (socialType == SocialType.GOOGLE) {
            return ofGoogle(userNameAttributeName, attributes);
        }
        if (socialType == SocialType.NAVER) {
            return ofNaver(userNameAttributeName, attributes);
        }
        return null;
    }

    public static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new GoogleOAuth2UserInfo(attributes))
                .build();
    }

    public static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new NaverOAuth2UserInfo(attributes))
                .build();
    }

    public User toUserEntity(SocialType socialType, OAuth2UserInfo oAuth2UserInfo) {
        return User.builder()
                .socialType(socialType)
                .socialId(oAuth2UserInfo.getId())
                .email(oAuth2UserInfo.getEmail())
                .nickname(oAuth2UserInfo.getNickname())
                .imageUrl(oAuth2UserInfo.getImageUrl())
                .role(Role.USER)
                .build();
    }

    public Email toEmailEntity(SocialType socialType, OAuth2UserInfo oAuth2UserInfo, Optional<User> byEmail) {

        log.info("toEmailEntity byEmail: {}", byEmail);
        return Email.builder()
                .email(oAuth2UserInfo.getEmail())
                .socialType(socialType)
                .socialId(oAuth2UserInfo.getId())
                .role(Role.USER)
                .nickname(oAuth2UserInfo.getNickname())
                .user(byEmail.get())
                .build();

    }

    /**
     *  DB 에 email 정보를 통해 중복체크할 필요가 있음.
     *  해당 로직이 있는지 확인
     */

}
