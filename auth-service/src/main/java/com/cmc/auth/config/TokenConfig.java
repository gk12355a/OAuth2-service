package com.cmc.auth.config;

// 1. Import các class của thư viện Nimbus (JOSE)
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey; // <-- Quan trọng: Dùng RSAKey của Nimbus
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

// 2. Import các class của Java Security (Tránh dùng .* để không bị conflict RSAKey)
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

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
        
        // [SỬA LỖI]: Thêm <SecurityContext> vào ImmutableJWKSet để Java hiểu kiểu
        return new ImmutableJWKSet<>(jwkSet); 
    }

    private RSAKey generateRsa() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Decode Public Key
            byte[] publicBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicSpec);

            // Decode Private Key
            byte[] privateBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateBytes);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateSpec);

            // Tạo RSAKey của Nimbus (Dùng để ký token)
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Lỗi load RSA Key từ config", e);
        }
    }
}