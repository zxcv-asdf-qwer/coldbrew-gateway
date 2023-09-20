package co.kr.compig.coldbrew.modules;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@Slf4j
@RestController
@RequestMapping(path = "/")
@RequiredArgsConstructor
public class IndexController {

    @GetMapping
    public ResponseEntity<String> index(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
//    public ResponseEntity<CustomAuthentication> index() {
//        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;
//        OAuth2AccessToken accessToken = customAuthentication.getAccessToken();
//        return ResponseEntity.ok().headers((headers) -> headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue())).body(customAuthentication);
        return ResponseEntity.ok("뭐냐");
    }

}
