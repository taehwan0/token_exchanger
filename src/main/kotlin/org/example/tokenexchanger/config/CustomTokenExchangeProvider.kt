package org.example.tokenexchanger.config

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

        authentication ?: throw OAuth2AuthenticationException("authentication is null")

        val tokenExchangeAuthentication = authentication as OAuth2TokenExchangeAuthenticationToken

        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(tokenExchangeAuthentication)
        val registeredClient = clientPrincipal.registeredClient

        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName("user")
            .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
            .authorizedScopes(authentication.scopes)
            .attribute(Principal::class.java.name, authentication.principal)

        val subjectAuthorization = authorizationBuilder.build()

        val tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .authorization(subjectAuthorization)
            .principal(authentication.principal as Authentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authentication.scopes)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
            .authorizationGrant(tokenExchangeAuthentication)

        val tokenContext = tokenContextBuilder.build()

        val generatedAccessToken = this.tokenGenerator.generate(tokenContext) as OAuth2Token

        val accessToken = accessToken(
            authorizationBuilder,
            generatedAccessToken,
            tokenContext
        )

        val refreshTokenContext = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .authorization(subjectAuthorization)
            .principal(authentication.principal as Authentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authentication.scopes)
            .tokenType(OAuth2TokenType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
            .authorizationGrant(tokenExchangeAuthentication)
            .build()

        val refreshToken = this.tokenGenerator.generate(refreshTokenContext)
        val currentRefreshToken = if (refreshToken is OAuth2RefreshToken) refreshToken else null

        val createdAuthorization = OAuth2Authorization.from(subjectAuthorization)
            .accessToken(accessToken)
            .refreshToken(currentRefreshToken)
            .build()

        authorizationService.save(createdAuthorization)

        // TODO: id_token 사용 시 additional parameters 사용해 넣을 것
        return OAuth2AccessTokenAuthenticationToken(
            registeredClient,
            clientPrincipal,
            accessToken,
            currentRefreshToken,
            mutableMapOf()
        )
    }

    override fun supports(authentication: Class<*>?): Boolean {
        println("supports method called $authentication")
        authentication?.let {
            return OAuth2TokenExchangeAuthenticationToken::class.java.isAssignableFrom(authentication)
        }
        return false
    }

    private fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
        var clientPrincipal: OAuth2ClientAuthenticationToken? = null
        if (OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication.principal.javaClass)) {
            clientPrincipal = authentication.principal as OAuth2ClientAuthenticationToken
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
            return clientPrincipal
        }
        throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
    }

    private fun <T : OAuth2Token?> accessToken(
        builder: OAuth2Authorization.Builder,
        token: T,
        accessTokenContext: OAuth2TokenContext
    ): OAuth2AccessToken {
        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, token!!.tokenValue,
            token.issuedAt, token.expiresAt, accessTokenContext.authorizedScopes
        )
        val accessTokenFormat = accessTokenContext.registeredClient
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