package com.cmc.auth.service;

import com.cmc.auth.config.RabbitMQConfig;
import com.cmc.auth.dto.RegisterRequest;
import com.cmc.auth.entity.Role;
import com.cmc.auth.entity.User;
import com.cmc.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, RabbitTemplate rabbitTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
    }

    public String register(RegisterRequest request) {
        // 1. Kiểm tra trùng username
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username đã tồn tại!");
        }

        // 2. Mã hóa mật khẩu
        // Vì dùng DelegatingPasswordEncoder, ta nên để prefix {bcrypt} cho rõ ràng
        // (Mặc dù default đã set là bcrypt, nhưng thêm vào cho chuẩn format mới)
        String rawPassword = request.getPassword();
        String encodedPassword = passwordEncoder.encode(rawPassword); 
        // Lưu ý: encoder.encode() của Delegating đã tự thêm prefix {bcrypt} rồi.

        // 3. Set quyền mặc định (USER)
        Set<Role> roles = new HashSet<>();
        roles.add(Role.ROLE_USER);

        // 4. Tạo User
        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setPassword(encodedPassword);
        newUser.setFullName(request.getFullName());
        newUser.setRoles(roles);
        newUser.setActive(true);

        userRepository.save(newUser);
        Map<String, Object> userSyncData = Map.of(
            "username", newUser.getUsername(),
            "fullName", newUser.getFullName(),
            "email", newUser.getUsername() // Giả sử username là email
        );

        rabbitTemplate.convertAndSend(
            RabbitMQConfig.EXCHANGE_NAME, 
            RabbitMQConfig.ROUTING_KEY, 
            userSyncData
        );

        return "Đăng ký tài khoản thành công!";
    }
}