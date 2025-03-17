package com.tuandanh.identityService.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tuandanh.identityService.entity.User;
import com.tuandanh.identityService.security.CustomOAuth2User;
import com.tuandanh.identityService.service.AuthenticationService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

    @Component
    @RequiredArgsConstructor
    public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

        private final AuthenticationService authenticationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        CustomOAuth2User customOAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        User user = customOAuth2User.getUser(); // Lấy User đã xử lý từ DB ra

        // Generate JWT
        String token = authenticationService.generateToken(user);

        // Trả về JSON
        Map<String, Object> tokenResponse = new HashMap<>();
        tokenResponse.put("accessToken", token);
        tokenResponse.put("tokenType", "Bearer");
        tokenResponse.put("expiresIn", 3600); // hoặc dynamic từ cấu hình

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(tokenResponse));
    }
}


