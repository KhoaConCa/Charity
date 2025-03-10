//package com.tuandanh.identityService.interceptor;
//
//import com.tuandanh.identityService.repository.UserRepository;
//import com.tuandanh.identityService.security.AuthenticationFacade;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//import org.springframework.web.servlet.HandlerInterceptor;
//
//import java.time.LocalDateTime;
//
//@Component
//public class UserActivityInterceptor implements HandlerInterceptor {
//
//    private final UserRepository userRepository;
//    private final AuthenticationFacade authenticationFacade;
//
//    @Autowired
//    public UserActivityInterceptor(UserRepository userRepository, AuthenticationFacade authenticationFacade) {
//        this.userRepository = userRepository;
//        this.authenticationFacade = authenticationFacade;
//    }
//
//    @Override
//    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
//        String username = authenticationFacade.getAuthenticatedUsername(); // Lấy thông tin user từ SecurityContext
//
//        if (username != null) {
//            userRepository.findByUsername(username).ifPresent(user -> {
//                user.setLastActiveAt(LocalDateTime.now()); // Cập nhật thời gian hoạt động
//                userRepository.save(user); // Lưu lại DB
//            });
//        }
//        return true; // Cho phép request tiếp tục thực hiện
//    }
//}
