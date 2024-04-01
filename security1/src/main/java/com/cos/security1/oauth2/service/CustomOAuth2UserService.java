package com.cos.security1.oauth2.service;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.oauth2.CustomOAuth2User;
import com.cos.security1.oauth2.OAuthAttributes;
import com.cos.security1.domain.user.entity.SocialType;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.oauth2.info.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final EmailRepository emailRepository;

    private static final String NAVER = "naver";
    private static final String GOOGLE = "google";


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser() 실행 - OAuth2 로그인 요청 진입");

        /**
         * DefaultOAuth2UserService 객체를 생성하여, loadUser(userRequest) 를 통해 DefaultOAuth2User 객체 생성 후 반환
         * DefaultOAuth2UserService 의 loadUser() 는 소셜 로그인 API 의 사용자 정보 제공 URI 로 요청을 보내서
         * 사용자 정보를 얻은 후, 이를 통해 DefaultOAuth2User 객체를 생성 후 반환한다.
         * 결과적으로, OAuth2User 는 OAuth2 서비스에서 가져온 유저 정보를 담고 있는 유저이다.
         */

        OAuth2User oAuth2User = createdOAuth2User(userRequest);

        /**
         * userRequest 에서 registrationId 추출 후 registrationId 로 SocialType 저장
         * http://localhost:8080/oauth2/authorization/naver 에서 naver 가 registrationId
         * userNameAttributeName 은 이후에 nameAttributeKey 로 설정된다.
         * userNameAttributeName 은 OAuth2 로그인 시 키(PK) 가 되는 값이다.
         */

        Map<String, Object> attributes = oAuth2User.getAttributes();
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);

        log.info("attributes: {}", attributes);




        if (socialType == (SocialType.NAVER)) {
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");
            String getEmail = response.get("email").toString();

            Optional<User> byEmail = userRepository.findByEmail(getEmail);
//
//            Optional<Email> findEmail = emailRepository.findBySocialTypeAndSocialId(socialType, registrationId);

            if (byEmail.isPresent()) {
                // email 테이블에 박을 데이터 생성 메서드
                createdCustomOAuth2Email(userRequest, byEmail);
            }
        }


        if (socialType == SocialType.GOOGLE) {
            String getEmail = attributes.get("email").toString();

            Optional<User> byEmail = userRepository.findByEmail(getEmail);
            if (byEmail.isPresent()) {
                // email 테이블에 박을 데이터 생성 메서드
                createdCustomOAuth2Email(userRequest, byEmail);


            }
        }
        return createdCustomOAuth2User(userRequest);
    }


    private CustomOAuth2User createdCustomOAuth2Email(OAuth2UserRequest userRequest, Optional<User> byEmail) {
        log.info("Email~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        OAuth2User oAuth2User = createdOAuth2User(userRequest);

        Map<String, Object> attributes = oAuth2User.getAttributes();
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes);

        Email createdEmail = getEmail(extractAttributes, socialType, byEmail);

        CustomOAuth2User oauth2 = new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(createdEmail.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdEmail.getEmail(),
                createdEmail.getRole());

        Authentication authentication = new UsernamePasswordAuthenticationToken(oauth2, null, oauth2.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return oauth2;
    }

    private CustomOAuth2User createdCustomOAuth2User(OAuth2UserRequest userRequest) {
        log.info("User~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        OAuth2User oAuth2User = createdOAuth2User(userRequest);

        Map<String, Object> attributes = oAuth2User.getAttributes();
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes);
        User createdUser = getUser(extractAttributes, socialType);
        CustomOAuth2User oauth2 = new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(createdUser.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdUser.getEmail(),
                createdUser.getRole());



        Authentication authentication = new UsernamePasswordAuthenticationToken(oauth2, null, oauth2.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);


        log.info("CustomOAuth2User: {}", oauth2);
        log.info("authentication: {}", authentication);

        return oauth2;

    }

    private SocialType getSocialType(String registrationId) {
        if (NAVER.equals(registrationId)) {
            return SocialType.NAVER;
        }
        if (GOOGLE.equals(registrationId)) {
            return SocialType.GOOGLE;
        }
        return null;
    }

    private User getUser(OAuthAttributes attributes, SocialType socialType) {
        User findUser = userRepository.findBySocialTypeAndSocialId(socialType,
                attributes.getOAuth2UserInfo().getId()).orElse(null);

        if (findUser == null) {
            return saveUser(attributes, socialType);
        }
        return findUser;
    }

    private User saveUser(OAuthAttributes attributes, SocialType socialType) {
        User createdUser = attributes.toUserEntity(socialType, attributes.getOAuth2UserInfo());
        return userRepository.save(createdUser);
    }

    private Email getEmail(OAuthAttributes attributes, SocialType socialType, Optional<User> byEmail) {
        Email findEmail = emailRepository.findBySocialTypeAndSocialId(socialType,
                attributes.getOAuth2UserInfo().getId()).orElse(null);

        if (findEmail == null) {
            return saveEmail(attributes, socialType, byEmail);
        }
        return findEmail;
    }

    private Email saveEmail(OAuthAttributes attributes, SocialType socialType, Optional<User> byEmail) {
        Email createdEmail = attributes.toEmailEntity(socialType, attributes.getOAuth2UserInfo(), byEmail);
        log.info("save Email ??  {}", createdEmail);
        return emailRepository.save(createdEmail);
    }

    private OAuth2User createdOAuth2User(OAuth2UserRequest userRequest) {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        return delegate.loadUser(userRequest);
    }

}
