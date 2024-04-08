package com.cos.security1;

import com.cos.security1.jwt.JwtService;
import com.cos.security1.jwt.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import com.cos.security1.jwt.filter.JwtAuthenticationProcessingFilter;
import com.cos.security1.jwt.handler.LoginFailureHandler;
import com.cos.security1.jwt.handler.LoginSuccessHandler;
import com.cos.security1.jwt.service.LoginService;
import com.cos.security1.oauth2.filter.CustomAuthenticationFilter;
import com.cos.security1.oauth2.filter.CustomAuthenticationProvider;
import com.cos.security1.oauth2.handler.OAuth2LoginFailureHandler;
import com.cos.security1.oauth2.handler.OAuth2LoginSuccessHandler;
import com.cos.security1.oauth2.service.CustomOAuth2UserService;
import com.cos.security1.domain.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final LoginService loginService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
    private final CustomOAuth2UserService customOAuth2UserService;




//    @Bean
//    public WebSecurityCustomizer configure() {
//        return (web -> web.ignoring()
//                .requestMatchers(new AntPathRequestMatcher("/")));
//    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(form -> form
                        .loginPage("/login").permitAll()
                )
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .headers(header -> header.
                        frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
                )
//                .sessionManagement(manager -> manager
//                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                )
                .authorizeHttpRequests(req -> req
                        .requestMatchers("/","/css/**","/images/**","/js/**","/favicon.ico").permitAll()
                        .requestMatchers("/loginForm", "/login").permitAll()
                        .requestMatchers("/sign-up").permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/")).permitAll()
                        .anyRequest().permitAll()
                )
//                .authenticationProvider(new CustomAuthenticationProvider())
                .oauth2Login(oauth -> oauth
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureHandler(oAuth2LoginFailureHandler)
                        .userInfoEndpoint(end -> end
                                .userService(customOAuth2UserService)
                        )
                );

        // 원래 스프링 시큐리티 필터 순서가 LogoutFilter 이후에 로그인 필터 동작
        // 따라서, LogoutFilter 이후에 우리가 만든 필터 동작하도록 설정
        // 순서 : LogoutFilter -> JwtAuthenticationProcessingFilter -> CustomJsonUsernamePasswordAuthenticationFilter


        http.addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationProcessingFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class);
//        http.addFilterAfter(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

//    @Bean
//    public CustomAuthenticationFilter customAuthenticationFilter() throws Exception {
//        return new CustomAuthenticationFilter(authenticationManager());
//    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * AuthenticationManager 설정 후 등록
     * PasswordEncoder를 사용하는 AuthenticationProvider 지정 (PasswordEncoder는 위에서 등록한 PasswordEncoder 사용)
     * FormLogin(기존 스프링 시큐리티 로그인)과 동일하게 DaoAuthenticationProvider 사용
     * UserDetailsService는 커스텀 LoginService로 등록
     * 또한, FormLogin과 동일하게 AuthenticationManager로는 구현체인 ProviderManager 사용(return ProviderManager)
     *
     */

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(loginService);
        return new ProviderManager(provider);
    }

    /**
     * 로그인 성공 시 호출되는 LoginSuccessJWTProviderHandler 빈 등록
     */
    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, userRepository);
    }

    /**
     * 로그인 실패 시 호출되는 LoginFailureHandler 빈 등록
     */
    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    /**
     * CustomJsonUsernamePasswordAuthenticationFilter 빈 등록
     * 커스텀 필터를 사용하기 위해 만든 커스텀 필터를 Bean으로 등록
     * setAuthenticationManager(authenticationManager())로 위에서 등록한 AuthenticationManager(ProviderManager) 설정
     * 로그인 성공 시 호출할 handler, 실패 시 호출할 handler로 위에서 등록한 handler 설정
     */
    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {
        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordLoginFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper);
        customJsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        customJsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordLoginFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
        JwtAuthenticationProcessingFilter jwtAuthenticationFilter = new JwtAuthenticationProcessingFilter(jwtService, userRepository);
        return jwtAuthenticationFilter;
    }

}
