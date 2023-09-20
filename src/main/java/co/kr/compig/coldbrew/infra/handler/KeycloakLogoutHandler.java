package co.kr.compig.coldbrew.infra.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;


@Slf4j
@Component
@RequiredArgsConstructor
public class KeycloakLogoutHandler implements ServerLogoutHandler {

    private final WebClient webClient;

    @Override
    public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
        return logoutFromKeycloak((OidcUser) authentication.getPrincipal());
    }

    private Mono<Void> logoutFromKeycloak(OidcUser user) {
        String endSessionEndpoint = user.getIssuer() + "/protocol/openid-connect/logout";
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(endSessionEndpoint)
                .queryParam("id_token_hint", user.getIdToken().getTokenValue());

        return webClient.get()
                .uri(builder.toUriString())
                .exchangeToMono(response -> {
                    if (!response.statusCode().is2xxSuccessful()) {
                        log.error("Could not propagate logout to Keycloak");
                    }
                    log.info("Successfulley logged out from Keycloak");
                    return response.bodyToMono(String.class);
                })
                .doOnError(WebClientResponseException.class, ex -> log.info("KeycloakLogoutHandler - logoutFromKeycloak : {}", ex))
                .then();
    }


}
