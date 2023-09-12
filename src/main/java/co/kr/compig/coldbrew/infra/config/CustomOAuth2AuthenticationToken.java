package co.kr.compig.coldbrew.infra.config;

import co.kr.compig.coldbrew.infra.CustomAuthentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;

public class CustomOAuth2AuthenticationToken extends OAuth2AuthenticationToken implements CustomAuthentication {
	private final String providerId;
	private final Integer numberOfStars;
	private final String name;
	private final boolean admin;

	public CustomOAuth2AuthenticationToken(OAuth2AuthenticationToken parentAuthentication) {
		super(parentAuthentication.getPrincipal(), parentAuthentication.getAuthorities(), parentAuthentication.getAuthorizedClientRegistrationId());
		this.providerId = parentAuthentication.getAuthorizedClientRegistrationId();
		Integer numberOfStars = parentAuthentication.getPrincipal().getAttribute("number_of_stars");
		this.numberOfStars = numberOfStars != null ? numberOfStars : 0;
		this.admin = parentAuthentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.anyMatch("ROLE_USER"::equals);
		this.name = parentAuthentication.getPrincipal().getName();
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
}
