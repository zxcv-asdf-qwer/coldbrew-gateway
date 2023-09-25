package co.kr.compig.coldbrew.modules;

import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.result.view.RedirectView;


@Slf4j
@RestController
@RequestMapping
@RequiredArgsConstructor
public class IndexController {

    @GetMapping
    public ResponseEntity<String> index(@AuthenticationPrincipal OidcUser oidcUserInfo) {
//    public ResponseEntity<CustomAuthentication> index() {
//        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;
//        OAuth2AccessToken accessToken = customAuthentication.getAccessToken();
//        return ResponseEntity.ok().headers((headers) -> headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue())).body(customAuthentication);
        return ResponseEntity.ok("뭐냐");
    }

    @GetMapping("/logina")
    public String login(@RequestParam String codeVerifier) {
        return String.format("redirect:/?codeVerifier=%s", codeVerifier);
    }

}
