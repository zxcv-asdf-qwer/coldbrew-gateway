package co.kr.compig.coldbrew.infra.config;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.function.BiConsumer;

public class CustomServerOAuth2AuthorizationCodeAuthenticationTokenConverter extends ServerOAuth2AuthorizationCodeAuthenticationTokenConverter {
    private static final String DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private static final String DEFAULT_AUTHORIZATION_REQUEST_PATTERN = "/login/oauth2/code/{"
            + DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME + "}";

    private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";

    private static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;
    private final ServerWebExchangeMatcher authorizationRequestMatcher = new PathPatternParserServerWebExchangeMatcher(DEFAULT_AUTHORIZATION_REQUEST_PATTERN);

    public CustomServerOAuth2AuthorizationCodeAuthenticationTokenConverter(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        super(clientRegistrationRepository);
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        if (ObjectUtils.anyNull(request.getQueryParams().getFirst(OidcParameterNames.NONCE), request.getQueryParams().getFirst(PkceParameterNames.CODE_VERIFIER))) {
            return super.convert(exchange);
        }
        return this.authorizationRequestMatcher
                .matches(exchange)
                .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                .map(ServerWebExchangeMatcher.MatchResult::getVariables)
                .map((variables) -> variables.get(DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME))
                .cast(String.class)
                .flatMap((clientRegistrationId) -> authorizationRequest(exchange, clientRegistrationId))
                .switchIfEmpty(oauth2AuthorizationException(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE))
                .flatMap((authorizationRequest) -> authenticationRequest(exchange, authorizationRequest));
    }


    private Mono<Authentication> authenticationRequest(ServerWebExchange exchange,
                                                       OAuth2AuthorizationRequest authorizationRequest) {
        // @formatter:off
        return Mono.just(authorizationRequest)
                .map(OAuth2AuthorizationRequest::getAttributes).flatMap((attributes) -> {
                    String id = (String) attributes.get(OAuth2ParameterNames.REGISTRATION_ID);
                    if (id == null) {
                        return oauth2AuthorizationException(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE);
                    }
                    return this.clientRegistrationRepository.findByRegistrationId(id);
                })
                .switchIfEmpty(oauth2AuthorizationException(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE))
                .map((clientRegistration) -> {
                    OAuth2AuthorizationResponse authorizationResponse = convertResponse(exchange);
                    OAuth2AuthorizationCodeAuthenticationToken authenticationRequest = new OAuth2AuthorizationCodeAuthenticationToken(
                            clientRegistration,
                            new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
                    return authenticationRequest;
                });
        // @formatter:on
    }

    private <T> Mono<T> oauth2AuthorizationException(ServerWebExchange exchange) {
        return (Mono<T>) Mono.firstWithSignal(super.convert(exchange));
    }

    private <T> Mono<T> oauth2AuthorizationException(String errorCode) {
        return Mono.defer(() -> {
            OAuth2Error oauth2Error = new OAuth2Error(errorCode);
            return Mono.error(new OAuth2AuthorizationException(oauth2Error));
        });
    }

    private static OAuth2AuthorizationResponse convertResponse(ServerWebExchange exchange) {
        String code = exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.CODE);
        String state = exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE);
        String redirectUri = UriComponentsBuilder.fromUri(exchange.getRequest().getURI()).build().toUriString();

        return OAuth2AuthorizationResponse.success(code).redirectUri(redirectUri).state(state).build();
    }

    private Mono<OAuth2AuthorizationRequest> authorizationRequest(ServerWebExchange exchange, String clientRegistrationId) {
        return this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
                .switchIfEmpty(
                        Mono.error(new NullPointerException(String.format("%s - clientRegistration is null", clientRegistrationId))))
                .mapNotNull((clientRegistration) -> {
                    OAuth2AuthorizationRequest.Builder builder = getBuilder(clientRegistration);
                    authorizationRequestCustomizer(exchange.getRequest()).accept(clientRegistration, builder);
                    return builder.build();
                });
    }

    private BiConsumer<ClientRegistration, OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer(ServerHttpRequest request) {
        String nonce = request.getQueryParams().getFirst(OidcParameterNames.NONCE);
        String codeVerifier = request.getQueryParams().getFirst(PkceParameterNames.CODE_VERIFIER);

        return (clientRegistration, builder) ->
                builder.clientId(clientRegistration.getClientId())
                        .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                        .redirectUri(clientRegistration.getRedirectUri())
                        .scopes(clientRegistration.getScopes())
                        .state(request.getQueryParams().getFirst(OAuth2ParameterNames.STATE))
                        .attributes((attrs) -> {
                            attrs.put(OidcParameterNames.NONCE, nonce);
                            attrs.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
                        })
                        .additionalParameters((params) -> {
                            try {
                                String nonceHash = createHash(Objects.requireNonNull(nonce));
                                String codeChallenge = createHash(Objects.requireNonNull(codeVerifier));
                                params.put(OidcParameterNames.NONCE, nonceHash);
                                params.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
                                params.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
                            } catch (NoSuchAlgorithmException ex) {
                                params.put(PkceParameterNames.CODE_CHALLENGE, codeVerifier);
                            }
                        });
    }

    private static String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private OAuth2AuthorizationRequest.Builder getBuilder(ClientRegistration clientRegistration) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
            return OAuth2AuthorizationRequest.authorizationCode()
                    .attributes((attrs) ->
                            attrs.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId()));
        }
        throw new IllegalArgumentException(
                "Invalid Authorization Grant Type (" + clientRegistration.getAuthorizationGrantType().getValue()
                        + ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
    }
}
