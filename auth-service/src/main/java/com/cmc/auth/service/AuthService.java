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
        // Kiểm tra username đã tồn tại chưa
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username đã tồn tại!");
        }

        // Mã hóa mật khẩu
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        // Gán vai trò mặc định
        Set<Role> roles = new HashSet<>();
        roles.add(Role.ROLE_USER);

        // Tạo user mới
        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setPassword(encodedPassword);
        newUser.setFullName(request.getFullName());
        newUser.setRoles(roles);
        newUser.setActive(true);

        // Lưu trước để sinh ID (rất quan trọng)
        userRepository.save(newUser);

        // Gửi thông tin đồng bộ bao gồm auth_id qua RabbitMQ
        Map<String, Object> userSyncData = Map.of(
            "auth_id", newUser.getId(),           // ID từ Auth Service - dùng để đồng bộ
            "username", newUser.getUsername(),
            "fullName", newUser.getFullName(),
            "email", newUser.getUsername()        // Giả sử username là email
        );

        rabbitTemplate.convertAndSend(
            RabbitMQConfig.EXCHANGE_NAME,
            RabbitMQConfig.ROUTING_KEY,
            userSyncData
        );

        return "Đăng ký tài khoản thành công!";
    }
}