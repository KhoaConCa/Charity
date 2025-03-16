package com.tuandanh.identityService.security;

import com.tuandanh.identityService.entity.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private final OAuth2User oAuth2User;
    // Getter cho phần mở rộng
    @Getter
    private final User user; // User đã xử lý xong
    @Getter
    private final OAuth2UserRequest userRequest; // Nếu muốn dùng luôn request sau này

    public CustomOAuth2User(OAuth2User oAuth2User, User user, OAuth2UserRequest userRequest) {
        this.oAuth2User = oAuth2User;
        this.user = user;
        this.userRequest = userRequest;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oAuth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return oAuth2User.getAuthorities();
    }

    @Override
    public String getName() {
        return oAuth2User.getName();
    }
}
