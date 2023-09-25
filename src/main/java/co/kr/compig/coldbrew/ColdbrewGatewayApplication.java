package co.kr.compig.coldbrew;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;


@SpringBootApplication
public class ColdbrewGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(ColdbrewGatewayApplication.class, args);
	}

}
