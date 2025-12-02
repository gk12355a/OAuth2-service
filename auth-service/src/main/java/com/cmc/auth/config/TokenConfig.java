package com.cmc.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TokenConfig {

    @Value("${auth.rsa.public-key}")
    private String publicKeyStr;

    @Value("${auth.rsa.private-key}")
    private String privateKeyStr;

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private RSAKey generateRsa() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            byte[] publicBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicSpec);

            byte[] privateBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateBytes);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateSpec);

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID("meeting-auth-key-id") 
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Lỗi load RSA Key từ config", e);
        }
    }
}