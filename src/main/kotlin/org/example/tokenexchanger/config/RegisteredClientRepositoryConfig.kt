package org.example.tokenexchanger.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.Duration
import java.util.*

@Configuration
class RegisteredClientRepositoryConfig {
    /**
     * 인증을 요청하는 Client에 대한 정의
     */
    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("oidc-client")
            // 평문으로 사용하는 경우 앞에 {noop}을 붙인다.
            .clientSecret("{noop}secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
            .redirectUri("http://localhost:8080/login/oauth2/code/oidc-client")
            .postLogoutRedirectUri("http://localhost:8080/")
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.OPENID)
            .tokenSettings(
                TokenSettings
                    .builder()
                    .reuseRefreshTokens(false) // refresh token rotation
                    .accessTokenTimeToLive(Duration.ofHours(2))
                    .refreshTokenTimeToLive(Duration.ofDays(30))
                    .build()
            )
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(true)
                    .build()
            )
            .build()

        return InMemoryRegisteredClientRepository(oidcClient)
    }
}