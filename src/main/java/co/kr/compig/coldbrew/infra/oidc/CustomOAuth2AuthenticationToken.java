package co.kr.compig.coldbrew.infra.oidc;

import co.kr.compig.coldbrew.infra.CustomAuthentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public class CustomOAuth2AuthenticationToken extends OAuth2AuthenticationToken implements CustomAuthentication {
    private final String providerId;
    private final Integer numberOfStars;
    private final String name;
    private final boolean admin;
    private final OAuth2AccessToken accessToken;

    public CustomOAuth2AuthenticationToken(OAuth2LoginAuthenticationToken parentAuthentication) {
        super(parentAuthentication.getPrincipal(), parentAuthentication.getAuthorities(), parentAuthentication.getClientRegistration().getRegistrationId());
        this.providerId = parentAuthentication.getClientRegistration().getRegistrationId();
        Integer numberOfStars = parentAuthentication.getPrincipal().getAttribute("number_of_stars");
        this.numberOfStars = numberOfStars != null ? numberOfStars : 0;
        this.admin = parentAuthentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_USER"::equals);
        this.name = parentAuthentication.getPrincipal().getAttribute("preferred_username");
        this.accessToken = parentAuthentication.getAccessToken();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getProviderName() {
        return providerId;
    }

    @Override
    public int getNumberOfStars() {
        return this.numberOfStars;
    }

    @Override
    public boolean isAdmin() {
        return this.admin;
    }

    @Override
    public OAuth2AccessToken getAccessToken() {
        return this.accessToken;
    }
}
