package org.example.tokenexchanger.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@Configuration
class TokenConfig {
    companion object {
        fun generateRsaKey(): KeyPair {
            try {
                val generator = KeyPairGenerator.getInstance("RSA")
                generator.initialize(2048)
                return generator.generateKeyPair()
            } catch (e: Exception) {
                throw IllegalStateException("Could not generate private key", e)
            }
        }
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keypair = generateRsaKey()
        val publicKey = keypair.public as RSAPublicKey
        val privateKey = keypair.private as RSAPrivateKey

        val rsaKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()

        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder {
        return NimbusJwtEncoder(jwkSource)
    }

    @Bean
    fun tokenGenerator(jwtEncoder: JwtEncoder): OAuth2TokenGenerator<OAuth2Token> {
        val jwtGenerator = JwtGenerator(jwtEncoder)
        // opaque access token 사용이 필요한 경우에 추가?
//        val accessTokenGenerator = OAuth2AccessTokenGenerator()
        val refreshTokenGenerator = OAuth2RefreshTokenGenerator()

        return DelegatingOAuth2TokenGenerator(
            jwtGenerator,
            refreshTokenGenerator
        )
    }
}