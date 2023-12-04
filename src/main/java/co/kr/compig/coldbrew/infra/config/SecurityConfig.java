package co.kr.compig.coldbrew.infra.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.*;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2ClientProperties oAuth2ClientProperties;
    private final ObjectMapper objectMapper;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
        http.cors(ServerHttpSecurity.CorsSpec::disable);
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.authorizeExchange((exchange) -> exchange.pathMatchers("/actuator/**",  "/favicon.ico").permitAll().anyExchange().authenticated());
        http.oauth2Login(login -> {
            login.authorizationRequestResolver(authorizationRequestResolver(this.clientRegistrationRepository()));
        });
        AuthenticationWebFilter authenticationFilter = new CustomOAuth2LoginAuthenticationWebFilter(reactiveAuthenticationManager(),
                authorizedClientRepository, clientRegistrationRepository());

        http.addFilterBefore(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        http.logout(logout -> logout
                .requiresLogout(new PathPatternParserServerWebExchangeMatcher("/logout"))
                .logoutSuccessHandler(oidcLogoutSuccessHandler()));
        return http.build();
    }

    public ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository());
        oidcLogoutSuccessHandler.setLogoutSuccessUrl(URI.create("/"));
        return oidcLogoutSuccessHandler;
    }

    private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        return new CustomDefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
    }

    @Bean
    public ReactiveClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = new ArrayList<>(
                new OAuth2ClientPropertiesMapper(oAuth2ClientProperties).asClientRegistrations().values());
        return new InMemoryReactiveClientRegistrationRepository(registrations);
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
        OAuth2LoginReactiveAuthenticationManager oauth2Manager = new OAuth2LoginReactiveAuthenticationManager(
                client, new DefaultReactiveOAuth2UserService());
        OidcAuthorizationCodeReactiveAuthenticationManager oidc = new OidcAuthorizationCodeReactiveAuthenticationManager(
                client, new OidcReactiveOAuth2UserService());
        return new DelegatingReactiveAuthenticationManager(oidc, oauth2Manager);
    }


    @Bean
    public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();

        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            return delegate.loadUser(userRequest)
                    .flatMap((oidcUser) -> {
                        OAuth2AccessToken accessToken = userRequest.getAccessToken();
                        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                        try {
                            SignedJWT jwt = SignedJWT.parse(accessToken.getTokenValue());
                            String claimJsonString = jwt.getJWTClaimsSet().toString();

                            Collection<String> roles = new HashSet<>();
                            JsonNode treeNode = objectMapper.readTree(claimJsonString);
                            List<JsonNode> jsonNodes = treeNode.findValues("roles");
                            jsonNodes.forEach(jsonNode -> {
                                if (jsonNode.isArray()) {
                                    jsonNode.elements().forEachRemaining(e -> {
                                        roles.add(e.asText());
                                    });
                                } else {
                                    roles.add(jsonNode.asText());
                                }
                            });

                            jsonNodes = treeNode.findValues("authorities");
                            jsonNodes.forEach(jsonNode -> {
                                if (jsonNode.isArray()) {
                                    jsonNode.elements().forEachRemaining(e -> {
                                        roles.add(e.asText());
                                    });
                                } else {
                                    roles.add(jsonNode.asText());
                                }
                            });

                            for (String authority : roles) {
                                mappedAuthorities.add(new SimpleGrantedAuthority(authority));
                            }
                        } catch (Exception e) {
                            log.error("oauth2UserService Exception", e);
                        }
                        oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

                        return Mono.just(oidcUser);
                    });
        };
    }
//    @Bean
//    public WebSessionManager webSessionManager() {
//        // Emulate SessionCreationPolicy.STATELESS
//        return exchange -> Mono.empty();
//    }
}