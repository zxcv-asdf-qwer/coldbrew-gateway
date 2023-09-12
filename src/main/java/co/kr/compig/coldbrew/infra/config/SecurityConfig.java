package co.kr.compig.coldbrew.infra.config;

import co.kr.compig.coldbrew.infra.handler.KeycloakLogoutHandler;
import co.kr.compig.coldbrew.infra.converter.CustomTokenConverter;
import co.kr.compig.coldbrew.infra.oidc.CustomOAuth2LoginAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsUtils;

@Slf4j
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
class SecurityConfig {
    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(
                new OidcAuthorizationCodeAuthenticationProvider(new DefaultAuthorizationCodeTokenResponseClient(), new OidcUserService()),
                new OAuth2LoginAuthenticationProvider(new DefaultAuthorizationCodeTokenResponseClient(), new DefaultOAuth2UserService())
        );
    }

    @Bean
    public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {
        var customOAuth2LoginAuthenticationFilter = new CustomOAuth2LoginAuthenticationFilter(
                this.clientRegistrationRepository,
                this.oAuth2AuthorizedClientRepository,
                authenticationManager()
        );
        customOAuth2LoginAuthenticationFilter.setAuthenticationResultConverter(new CustomTokenConverter());
//        http.cors();
//        http.csrf();
        http.oauth2Login()
                .and()
                .addFilterBefore(customOAuth2LoginAuthenticationFilter, OAuth2LoginAuthenticationFilter.class);
        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .addLogoutHandler(keycloakLogoutHandler)
                .logoutSuccessUrl("/");

        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .anyRequest()
                .authenticated());

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        return http.build();
    }

}