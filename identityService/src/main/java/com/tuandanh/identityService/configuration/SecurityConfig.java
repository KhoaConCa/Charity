package com.tuandanh.identityService.configuration;

import com.tuandanh.identityService.security.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor // Tự tạo constructor chứa các bean final
@Slf4j
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOAuth2SuccessHandler customOAuth2SuccessHandler;

    @Value("${jwt.signerKey}")
    private String signerKey;

    private final String[] PUBLIC_ENDPOINTS1 = {
            "/users",
            "/auth/token",
            "/auth/introspect",
            "/auth/forgot-password",
            "/auth/reset-password",
            "/auth/send-otp",
            "/auth/verify-otp",
    };

    private final String[] PUBLIC_ENDPOINTS2 = {
            "/error",
            "/identity/v3/api-docs",
            "/identity/v3/api-docs/**",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/swagger-resources/**",
            "/api-docs/**",
            "/webjars/**", // thêm dòng này để load js, css
            "/swagger-ui/swagger-ui-bundle.js"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        log.error("endpoint : " + String.join(", ", PUBLIC_ENDPOINTS2));


        httpSecurity.authorizeHttpRequests(request -> request
                .requestMatchers(PUBLIC_ENDPOINTS2).permitAll()
                .requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINTS1).permitAll()
                .requestMatchers("/ws/**").permitAll() // Các endpoint public
                .requestMatchers("/roles/**").hasRole("ADMIN")  // Chỉ admin mới có thể truy cập /roles/**
                .requestMatchers("/permissions/**").hasRole("ADMIN")
                .anyRequest().authenticated());  // Mọi request khác phải xác thực

        // Cấu hình OAuth2 Login
        httpSecurity.oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/google")
                .successHandler(customOAuth2SuccessHandler) // Xử lý khi login thành công
                .failureUrl("/oauth2/failure") // Xử lý khi thất bại
                .userInfoEndpoint(userInfo -> userInfo
                        .userService(customOAuth2UserService) // Custom xử lý user info
                )
        );

        httpSecurity.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwtConfigurer -> jwtConfigurer
                        .decoder(jwtDecoder())
                        .jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint()));

        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        return httpSecurity.build();
    }

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedOrigin("*");
        config.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");
        return NimbusJwtDecoder
                .withSecretKey(secretKeySpec)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
