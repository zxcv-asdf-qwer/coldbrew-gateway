package co.kr.compig.coldbrew.infra.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfiguration {

    @Bean
    WebClient webClient(ReactiveClientRegistrationRepository reactiveClientRegistrationRepository,
                        ServerOAuth2AuthorizedClientRepository serverOAuth2AuthorizedClientRepository) {
        ServerOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
                new ServerOAuth2AuthorizedClientExchangeFilterFunction(reactiveClientRegistrationRepository, serverOAuth2AuthorizedClientRepository);
        oauth2.setDefaultClientRegistrationId("keycloak");
        return WebClient.builder()
                .filter(oauth2)
//                .clientConnector(clientHttpConnector())
                .build();
    }

//    @Bean
//    public ClientHttpConnector clientHttpConnector() {
//        return new ReactorClientHttpConnector(HttpClient.create(
//                        ConnectionProvider
//                                .builder("coldbrew")
//                                .maxConnections(25)
//                                .pendingAcquireMaxCount(-1)
//                                .pendingAcquireTimeout(Duration.ofMinutes(15))
//                                .maxLifeTime(Duration.ofMinutes(30))
//                                .maxIdleTime(Duration.ofMinutes(5))
//                                .build())
//                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 900000)
//                .option(ChannelOption.SO_KEEPALIVE, true)
//                .option(EpollChannelOption.TCP_KEEPIDLE, 300)
//                .option(EpollChannelOption.TCP_KEEPINTVL, 60)
//                .option(EpollChannelOption.TCP_KEEPCNT, 8)
//                .responseTimeout(Duration.ofMinutes(10))
//        );
//    }
}
