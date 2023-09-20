package co.kr.compig.coldbrew.infra.config;

import co.kr.compig.coldbrew.infra.handler.KeycloakLogoutHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final OAuth2ClientProperties oAuth2ClientProperties;
    @Bean
    public SecurityWebFilterChain pkceFilterChain(ServerHttpSecurity http) {
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.authorizeExchange(r -> r.anyExchange().authenticated());
        http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
        http.oauth2Login(login-> login.clientRegistrationRepository(this.clientRegistrationRepository()).authorizationRequestResolver(pkceResolver()));
        http.oauth2Client(oauth2 -> oauth2.clientRegistrationRepository(this.clientRegistrationRepository()).authorizationRequestResolver(pkceResolver()));
        http.logout(logout -> logout
                .logoutHandler(this.keycloakLogoutHandler)
                .logoutSuccessHandler(oidcLogoutSuccessHandler(this.clientRegistrationRepository())));
        return http.build();
    }
    @Bean
    public ServerOAuth2AuthorizationRequestResolver pkceResolver() {
        DefaultServerOAuth2AuthorizationRequestResolver resolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(this.clientRegistrationRepository());
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler(ReactiveClientRegistrationRepository repo) {
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(repo);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

        return oidcLogoutSuccessHandler;
    }

    private ReactiveClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = new ArrayList<>(
                new OAuth2ClientPropertiesMapper(oAuth2ClientProperties).asClientRegistrations().values());
        return new InMemoryReactiveClientRegistrationRepository(registrations);
    }
}