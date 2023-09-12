package co.kr.compig.coldbrew.infra.oidc;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;

public class CustomOAuth2LoginAuthenticationFilter extends OAuth2LoginAuthenticationFilter {

    public CustomOAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository, AuthenticationManager authenticationManager) {
        super(clientRegistrationRepository, authorizedClientRepository, DEFAULT_FILTER_PROCESSES_URI);
        super.setAuthorizationRequestRepository(new HttpSessionOAuth2AuthorizationRequestRepository());
        super.setAuthenticationManager(authenticationManager);
    }
}
