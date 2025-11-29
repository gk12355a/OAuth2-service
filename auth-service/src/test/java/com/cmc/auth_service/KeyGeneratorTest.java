package com.cmc.auth_service; // <--- Hãy sửa tên package này cho khớp với thư mục của bạn nếu báo lỗi đỏ

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class KeyGeneratorTest {

    // Đổi từ @Test thành public static void main
    public static void main(String[] args) throws Exception {
        
        // 1. Khởi tạo thuật toán RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        
        // 2. Sinh cặp khóa
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 3. Mã hóa sang Base64
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        // 4. In kết quả
        System.out.println("\n========== COPY VAO .ENV ==========");
        System.out.println("RSA_PRIVATE_KEY=" + privateKey);
        System.out.println("RSA_PUBLIC_KEY=" + publicKey);
        System.out.println("===================================\n");
    }
}