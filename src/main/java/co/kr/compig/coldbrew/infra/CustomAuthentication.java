package co.kr.compig.coldbrew.infra;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public interface CustomAuthentication extends Authentication {

    String getProviderName();

    int getNumberOfStars();

    boolean isAdmin();

    String getName();

    OAuth2AccessToken getAccessToken();
}
