package co.kr.compig.coldbrew.modules;

import co.kr.compig.coldbrew.infra.CustomAuthentication;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(path = "/")
@RequiredArgsConstructor
public class IndexController {

    @GetMapping
    public ResponseEntity<CustomAuthentication> index(Authentication authentication) {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;
        OAuth2AccessToken accessToken = customAuthentication.getAccessToken();
        return ResponseEntity.ok().headers((headers) -> headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue())).body(customAuthentication);
    }

}
