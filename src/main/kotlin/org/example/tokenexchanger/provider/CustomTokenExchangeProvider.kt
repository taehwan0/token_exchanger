package org.example.tokenexchanger.provider

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import java.security.Principal

class CustomTokenExchangeProvider(
    private val tokenGenerator: OAuth2TokenGenerator<OAuth2Token>,
    private val authorizationService: OAuth2AuthorizationService
) : AuthenticationProvider {
    init {
        println("constructor called!!")
    }

    override fun authenticate(authentication: Authentication?): Authentication {
        println("authenticate method called $authentication")

        val tokenExchangeAuthentication = authentication as? OAuth2TokenExchangeAuthenticationToken
            ?: throw OAuth2AuthenticationException("authentication is null")

        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(tokenExchangeAuthentication)
        val registeredClient = clientPrincipal.registeredClient

        // TODO: 사용자 검증 및 정보 삽입 추가 필요!
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName("user")
            .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
            .authorizedScopes(authentication.scopes)
            .attribute(Principal::class.java.name, authentication.principal)

        val tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(authentication.principal as Authentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authentication.scopes)
            .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
            .authorizationGrant(tokenExchangeAuthentication)

        val accessTokenContext = tokenContextBuilder
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .build()

        val generatedAccessToken = this.tokenGenerator.generate(accessTokenContext)
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)

        // access token 발급 시 jwt 발급이 되기 때문에 jwt -> OAuth2AccessToken 타입으로 컨버팅하는 역할을 수행한다.
        val accessToken = convertTokenToOAuth2AccessToken(
            authorizationBuilder,
            generatedAccessToken,
            accessTokenContext
        )

        val refreshTokenContext = tokenContextBuilder
            .tokenType(OAuth2TokenType.REFRESH_TOKEN)
            .build()

        val refreshToken = this.tokenGenerator.generate(refreshTokenContext) as? OAuth2RefreshToken

        val authorization = authorizationBuilder
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build()

        authorizationService.save(authorization)

        // TODO: id_token 사용 시 additional parameters 사용해 넣을 것
        return OAuth2AccessTokenAuthenticationToken(
            registeredClient,
            clientPrincipal,
            accessToken,
            refreshToken,
            mutableMapOf()
        )
    }

    /**
     * 해당 AuthenticationProvider 가 요청을 처리할 수 있는지 타입을 확인한다.
     * support 반환값이 true 일 경우 authenticate 메서드를 수행해 인증(토큰생성)을 시도한다.
     */
    override fun supports(authentication: Class<*>?): Boolean {
        println("supports method called $authentication")
        authentication?.let {
            return OAuth2TokenExchangeAuthenticationToken::class.java.isAssignableFrom(authentication)
        }
        return false
    }

    private fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
        val clientPrincipal = authentication.principal as? OAuth2ClientAuthenticationToken
        if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
            return clientPrincipal
        }
        throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
    }

    private fun <T : OAuth2Token?> convertTokenToOAuth2AccessToken(
        builder: OAuth2Authorization.Builder,
        token: T,
        accessTokenContext: OAuth2TokenContext
    ): OAuth2AccessToken {
        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            token?.tokenValue ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST),
            token.issuedAt,
            token.expiresAt,
            accessTokenContext.authorizedScopes
        )
        val accessTokenFormat = accessTokenContext
            .registeredClient
            .tokenSettings
            .accessTokenFormat
        builder.token(accessToken) { metadata: MutableMap<String?, Any?> ->
            if (token is ClaimAccessor) {
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = token.claims
            }
            metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = false
            metadata[OAuth2TokenFormat::class.java.name] = accessTokenFormat.value
        }

        return accessToken
    }
}