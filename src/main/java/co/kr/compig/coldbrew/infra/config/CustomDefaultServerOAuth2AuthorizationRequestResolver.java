package co.kr.compig.coldbrew.infra.config;

import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;


public class CustomDefaultServerOAuth2AuthorizationRequestResolver extends DefaultServerOAuth2AuthorizationRequestResolver {
    public CustomDefaultServerOAuth2AuthorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        super(clientRegistrationRepository);
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
        return super.resolve(exchange, clientRegistrationId)
                .map(oAuth2AuthorizationRequest -> {
                    if (exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE) == null
                            || exchange.getRequest().getQueryParams().getFirst(PkceParameterNames.CODE_VERIFIER) == null) {
                        return oAuth2AuthorizationRequest;
                    }
                    OAuth2AuthorizationRequest.Builder from = OAuth2AuthorizationRequest.from(oAuth2AuthorizationRequest);

                    from.state(exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE));

                    String codeVerifier = exchange.getRequest().getQueryParams().getFirst(PkceParameterNames.CODE_VERIFIER);
                    from.attributes((attrs) -> attrs.replace(PkceParameterNames.CODE_VERIFIER, codeVerifier));

                    from.additionalParameters((params) -> {
                        try {
                            String codeChallenge = createHash(Objects.requireNonNull(codeVerifier));
                            params.replace(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
                        } catch (NoSuchAlgorithmException ex) {
                            params.replace(PkceParameterNames.CODE_CHALLENGE, codeVerifier);
                        }
                    });
                    return from.build();
                });
    }

    private String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
