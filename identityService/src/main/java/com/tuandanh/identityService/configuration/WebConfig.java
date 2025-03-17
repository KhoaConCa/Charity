//package com.tuandanh.identityService.configuration;
//
//import com.tuandanh.identityService.interceptor.UserActivityInterceptor;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
//@Configuration
//public class WebConfig implements WebMvcConfigurer {
//
//    private final UserActivityInterceptor userActivityInterceptor;
//
//    @Autowired
//    public WebConfig(UserActivityInterceptor userActivityInterceptor) {
//        this.userActivityInterceptor = userActivityInterceptor;
//    }
//
//    @Override
//    public void addInterceptors(InterceptorRegistry registry) {
//        registry.addInterceptor(userActivityInterceptor)
//                .addPathPatterns("/**"); // Áp dụng cho tất cả API
//    }
//}
