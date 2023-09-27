package co.kr.compig.coldbrew.infra.config;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.*;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import reactor.core.publisher.Mono;

public class CustomOAuth2LoginAuthenticationWebFilter extends AuthenticationWebFilter {

    private final ServerOAuth2AuthorizedClientRepository serverOAuth2AuthorizedClientRepository;

    public CustomOAuth2LoginAuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager
            , ServerOAuth2AuthorizedClientRepository authorizedClientRepository
            , ReactiveClientRegistrationRepository clientRegistrationRepository) {
        super(authenticationManager);
        this.serverOAuth2AuthorizedClientRepository = authorizedClientRepository;
        this.setRequiresAuthenticationMatcher(new PathPatternParserServerWebExchangeMatcher("/login/oauth2/code/{registrationId}"));
        this.setServerAuthenticationConverter(getAuthenticationConverter(clientRegistrationRepository));
        this.setAuthenticationSuccessHandler(getAuthenticationSuccessHandler());
        this.setAuthenticationFailureHandler(new RedirectServerAuthenticationFailureHandler("/login?error"));
        this.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
    }

    @Override
    protected Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
        OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) authentication;
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(), authenticationResult.getName(),
                authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
        return this.serverOAuth2AuthorizedClientRepository
                .saveAuthorizedClient(authorizedClient, authenticationResult, webFilterExchange.getExchange())
                .then(super.onAuthenticationSuccess(authenticationResult, webFilterExchange));
    }

    private ServerAuthenticationConverter getAuthenticationConverter(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        ServerOAuth2AuthorizationCodeAuthenticationTokenConverter delegate = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
                clientRegistrationRepository);
        delegate.setAuthorizationRequestRepository(new WebSessionOAuth2ServerAuthorizationRequestRepository());
        return (exchange) -> delegate.convert(exchange).onErrorMap(
                OAuth2AuthorizationException.class,
                (e) -> new OAuth2AuthenticationException(e.getError(), e.getError().toString()));
    }

    private ServerAuthenticationSuccessHandler getAuthenticationSuccessHandler() {
        RedirectServerAuthenticationSuccessHandler handler = new RedirectServerAuthenticationSuccessHandler();
        return handler;
    }
}
