package co.kr.compig.coldbrew.infra.converter;

import co.kr.compig.coldbrew.infra.oidc.CustomOAuth2AuthenticationToken;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;

public class CustomTokenConverter implements Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> {

    @Override
    public OAuth2AuthenticationToken convert(OAuth2LoginAuthenticationToken authentication) {
        return new CustomOAuth2AuthenticationToken(authentication);
    }
}