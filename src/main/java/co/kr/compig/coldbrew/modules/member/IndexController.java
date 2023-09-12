package co.kr.compig.coldbrew.modules.member;

import co.kr.compig.coldbrew.infra.CustomAuthentication;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    public String index(Authentication authentication) {
        return getAccessToken(authentication);
    }

    public String getAccessToken(Authentication authentication) {
        CustomAuthentication customAuth = (CustomAuthentication) authentication;
        return customAuth.getName();
    }
}
