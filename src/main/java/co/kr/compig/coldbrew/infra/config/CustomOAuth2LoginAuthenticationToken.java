package co.kr.compig.coldbrew.infra.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import co.kr.compig.coldbrew.infra.CustomAuthentication;

public class CustomOAuth2LoginAuthenticationToken extends OAuth2LoginAuthenticationToken implements CustomAuthentication {
	private final String providerId;
	private final Integer numberOfStars;
	private final String name;
	private final boolean admin;


	public CustomOAuth2LoginAuthenticationToken(OAuth2LoginAuthenticationToken parentAuthentication) {
		super(parentAuthentication.getClientRegistration(), parentAuthentication.getAuthorizationExchange(),
				parentAuthentication.getPrincipal(), parentAuthentication.getAuthorities(),
				parentAuthentication.getAccessToken(), parentAuthentication.getRefreshToken());
		this.providerId = parentAuthentication.getClientRegistration().getRegistrationId();
		this.numberOfStars = parentAuthentication.getPrincipal().getAttribute("number_of_stars");
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
