package com.cos.security1.oauth2.service;

import com.cos.security1.domain.email.Email;
import com.cos.security1.domain.email.repository.EmailRepository;
import com.cos.security1.domain.user.entity.User;
import com.cos.security1.jwt.InMemoryTokenStore;
import com.cos.security1.jwt.service.LoginService;
import com.cos.security1.oauth2.CustomOAuth2User;
import com.cos.security1.oauth2.OAuthAttributes;
import com.cos.security1.domain.user.entity.SocialType;
import com.cos.security1.domain.user.repository.UserRepository;
import com.cos.security1.oauth2.info.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import javax.swing.text.html.Option;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final EmailRepository emailRepository;
    private final InMemoryTokenStore tokenStore;

    private static final String NAVER = "naver";
    private static final String GOOGLE = "google";


    @SneakyThrows
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser() 실행 - OAuth2 로그인 요청 진입");

        OAuth2User oAuth2User = createdOAuth2User(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);

        String nickname = attributes.get("name").toString();
        String token = tokenStore.getToken(nickname);

        if (token != null) {
            log.info("oauth2 token: {}", token);
            tokenStore.removeToken("nickname");
            Optional<User> findUser = userRepository.findByNickname(nickname);

            return NormalUserUpdateEmail(userRequest, findUser);

        }

        /**
         * 만약 user Details 의 객체가
         */

        log.info("oAuth2User.getName, {}", oAuth2User.getName());
        log.info("attributes: {}", attributes);



        if (socialType == SocialType.GOOGLE) {
            Optional<Email> existingEmail = emailRepository.findBySocialTypeAndSocialId(socialType, attributes.get("sub").toString());
            log.info("OAuth2 로그인 요청: {}", existingEmail);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            log.info("authentcaiton 구조: {}", authentication);

            if (existingEmail.isPresent()) {
                return updateEmail(userRequest, authentication);
            } else {

                if (authentication != null && authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken)) {
                    return updateEmail(userRequest, authentication);

                } else {
                    return createdCustomOAuth2User(userRequest);
                }
            }
        }
        return (OAuth2User) new OAuth2AuthenticationException("google 과 naver 가 아닌 다른 플랫폼은 지원하지 않습니다.");
    }


    private CustomOAuth2User updateEmail(OAuth2UserRequest userRequest, Authentication authentication) throws Exception {


        /**
         * 1. userRequest 객체가 Email Entity 에 존재하는 경우 OR
         * 2. userRequest 객체가 Email Entity 에 존재하지 않고 Security Context 내에 Authorized 객체가 존재할 경우
         */

        OAuth2User oAuth2User = createdOAuth2User(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();
        // userRequest 부분


        log.info("CustomOAuth2Service 의 updateEmail: {}", authentication);
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) authentication;
        String registrationId = authenticationToken.getAuthorizedClientRegistrationId();
        // Security Context 인증 객체

        log.info("authentication: {}", authentication);
        log.info("authenticationToken: {}", authenticationToken);
        log.info("registrationId: {}", registrationId);


        OAuth2User principal = authenticationToken.getPrincipal();
        Map<String, Object> getAttribute = principal.getAttributes();
        String email = getAttribute.get("email").toString();

        Optional<Email> byEmail = emailRepository.findByEmail(email);

        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        String loginEmail = null;
        Optional<User> userEmail = Optional.empty();

        if (byEmail.isEmpty()) {

            userEmail = userRepository.findByEmail(email);

            OAuthAttributes extractAttributes = OAuthAttributes.of(SocialType.GOOGLE, userNameAttributeName, attributes);

            Email createdEmail = getEmail(extractAttributes, SocialType.GOOGLE, userEmail);
            return new CustomOAuth2User(Collections.singleton(new SimpleGrantedAuthority(createdEmail.getRole().getKey())),
                    attributes,
                    extractAttributes.getNameAttributeKey(),
                    createdEmail.getEmail(),
                    createdEmail.getRole());


        }

        /**
         * 이메일 레포지토리에 존재하는 경우
         * 즉, authentication 객체가 이메일 db 에 있는 것으로 변경됐으니
         * 이메일 entity 와 연관관계에 있는 user entity 로 연관관계를 매핑해 저장
         */
        loginEmail = byEmail.get().getUser().getEmail();
        userEmail = userRepository.findByEmail(loginEmail);

        OAuthAttributes extractAttributes = OAuthAttributes.of(SocialType.GOOGLE, userNameAttributeName, attributes);

        Email createdEmail = getEmail(extractAttributes, SocialType.GOOGLE, userEmail);
        return new CustomOAuth2User(Collections.singleton(new SimpleGrantedAuthority(createdEmail.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdEmail.getEmail(),
                createdEmail.getRole());




        // User 에 존재하는 인증 객체


//
//        if (userRequest.getClientRegistration().getRegistrationId().equals(NAVER)) {
//            OAuthAttributes extractAttributes = OAuthAttributes.of(SocialType.NAVER, userNameAttributeName, attributes);
//            Email createdEmail = getEmail(extractAttributes, SocialType.NAVER, loginEmail);
//
//            return new CustomOAuth2User(Collections.singleton(new SimpleGrantedAuthority(createdEmail.getRole().getKey())),
//                    attributes,
//                    extractAttributes.getNameAttributeKey(),
//                    createdEmail.getEmail(),
//                    createdEmail.getRole());
//        }
//        else {
//            OAuthAttributes extractAttributes = OAuthAttributes.of(SocialType.GOOGLE, userNameAttributeName, attributes);
//
//            Email createdEmail = getEmail(extractAttributes, SocialType.GOOGLE, byEmail);
//            return new CustomOAuth2User(Collections.singleton(new SimpleGrantedAuthority(createdEmail.getRole().getKey())),
//                    attributes,
//                    extractAttributes.getNameAttributeKey(),
//                    createdEmail.getEmail(),
//                    createdEmail.getRole());
//        }
    }

    private CustomOAuth2User NormalUserUpdateEmail(OAuth2UserRequest userRequest, Optional<User> findUser) {


        OAuth2User oAuth2User = createdOAuth2User(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        OAuthAttributes extractAttributes = OAuthAttributes.of(SocialType.GOOGLE, userNameAttributeName, attributes);

        Email createdEmail = getEmail(extractAttributes, SocialType.GOOGLE, findUser);
        return new CustomOAuth2User(Collections.singleton(new SimpleGrantedAuthority(createdEmail.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdEmail.getEmail(),
                createdEmail.getRole());
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

        log.info("이거는 한번만 와야해..");
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
        User user = userRepository.saveAndFlush(createdUser);
        Email createdEmail = attributes.toEmailEntity(socialType, attributes.getOAuth2UserInfo(), Optional.of(user));
        emailRepository.save(createdEmail);
        return user;
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
        log.info("save Email ??  {}", createdEmail.getEmail());
        log.info("save ByEmail ?? {}", byEmail.get().getEmail());

        return emailRepository.save(createdEmail);
    }

    private OAuth2User createdOAuth2User(OAuth2UserRequest userRequest) {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        return delegate.loadUser(userRequest);
    }

}

/**
 * DefaultOAuth2UserService 객체를 생성하여, loadUser(userRequest) 를 통해 DefaultOAuth2User 객체 생성 후 반환
 * DefaultOAuth2UserService 의 loadUser() 는 소셜 로그인 API 의 사용자 정보 제공 URI 로 요청을 보내서
 * 사용자 정보를 얻은 후, 이를 통해 DefaultOAuth2User 객체를 생성 후 반환한다.
 * 결과적으로, OAuth2User 는 OAuth2 서비스에서 가져온 유저 정보를 담고 있는 유저이다.
 */

/**
 * userRequest 에서 registrationId 추출 후 registrationId 로 SocialType 저장
 * http://localhost:8080/oauth2/authorization/naver 에서 naver 가 registrationId
 * userNameAttributeName 은 이후에 nameAttributeKey 로 설정된다.
 * userNameAttributeName 은 OAuth2 로그인 시 키(PK) 가 되는 값이다.
 */
