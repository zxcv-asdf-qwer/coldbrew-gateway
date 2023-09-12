package co.kr.compig.coldbrew.infra;

import org.springframework.security.core.Authentication;

public interface CustomAuthentication extends Authentication {

	String getProviderName();

	int getNumberOfStars();

	boolean isAdmin();

	String getName();
}
