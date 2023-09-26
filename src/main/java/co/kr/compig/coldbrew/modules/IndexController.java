package co.kr.compig.coldbrew.modules;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class IndexController {

    @GetMapping
    public ResponseEntity<OAuth2LoginAuthenticationToken> index(Authentication authentication) {
        OAuth2LoginAuthenticationToken auth2LoginAuthenticationTokenMono = (OAuth2LoginAuthenticationToken) authentication;
        OAuth2AccessToken accessToken = auth2LoginAuthenticationTokenMono.getAccessToken();
        return ResponseEntity.ok().headers((headers) -> headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue())).body(auth2LoginAuthenticationTokenMono);
    }
}
