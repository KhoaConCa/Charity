//package com.tuandanh.identityService.security;
//
//
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//
//@Component
//public class AuthenticationFacade {
//
//    public String getAuthenticatedUsername() {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
//            return authentication.getName(); // Username
//        }
//        return null; // Nếu chưa đăng nhập
//    }
//}
