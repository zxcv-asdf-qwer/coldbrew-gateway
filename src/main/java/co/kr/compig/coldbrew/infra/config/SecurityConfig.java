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
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.function.Consumer;

import static org.springframework.security.config.Customizer.withDefaults;

//8081 -> 8180
//builder.attribute.put(PkceParameterNames.CODE_VERIFIER, codeVerifier)
//builder.additionalParameter.put(PkceParameterNames.CODE_CHALLENGE, createHash(codeVerifier))
//builder.additionalParameter.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256")
@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2ClientProperties oAuth2ClientProperties;
    private final ObjectMapper objectMapper;

    //    private final ReactiveClientRegistrationRepository repo;
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http.cors(ServerHttpSecurity.CorsSpec::disable);
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.authorizeExchange((exchange) -> exchange.pathMatchers("/actuator/**", "/logina").permitAll().anyExchange().authenticated());
//        http.formLogin(ServerHttpSecurity.FormLoginSpec::disable);
//                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable);
        http.oauth2Login(login -> login.authorizationRequestResolver(authorizationRequestResolver(this.clientRegistrationRepository())));
        http.oauth2Client(withDefaults());

        http.logout(logout -> logout
                .requiresLogout(new PathPatternParserServerWebExchangeMatcher("/logout"))
                .logoutSuccessHandler(oidcLogoutSuccessHandler()));
        return http.build();
    }

    //    @Bean
    public ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository());
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

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
                        // TODO
                        // 1) Fetch the authority information from the protected resource using accessToken
                        // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities

                        // 3) Create a copy of oidcUser but use the mappedAuthorities instead
                        oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

                        return Mono.just(oidcUser);
                    });
        };
    }


}