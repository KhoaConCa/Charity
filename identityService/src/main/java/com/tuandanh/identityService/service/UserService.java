package com.tuandanh.identityService.service;

import com.tuandanh.identityService.constant.PredefinedRole;
import com.tuandanh.identityService.dto.request.ChangePasswordRequest;
import com.tuandanh.identityService.dto.request.UserCreationRequest;
import com.tuandanh.identityService.dto.request.UserUpdateRequest;
import com.tuandanh.identityService.dto.response.ChangePasswordResponse;
import com.tuandanh.identityService.dto.response.UserOnlineStatusResponse;
import com.tuandanh.identityService.dto.response.UserResponse;
import com.tuandanh.identityService.entity.Role;
import com.tuandanh.identityService.entity.User;
import com.tuandanh.identityService.exception.AppException;
import com.tuandanh.identityService.exception.ErrorCode;
import com.tuandanh.identityService.mapper.UserMapper;
import com.tuandanh.identityService.repository.RoleRepository;
import com.tuandanh.identityService.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserService {
    UserRepository userRepository;
    RoleRepository roleRepository;
    UserMapper userMapper;
    PasswordEncoder passwordEncoder;
    RedisTemplate<String, Object> redisTemplate;

    public UserResponse createUser(UserCreationRequest request) {
//        if (userRepository.existsByUsername(request.getUsername())) throw new AppException(ErrorCode.USER_EXISTED);

        User user = userMapper.toUser(request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        HashSet<Role> roles = new HashSet<>();
        roleRepository.findById(PredefinedRole.USER_ROLE).ifPresent(roles::add);

        user.setRoles(roles);

        return userMapper.toUserResponse(userRepository.save(user));
    }

    @PreAuthorize("hasRole('ADMIN') or returnObject.username == authentication.name")
    public UserResponse updateUser(String userId, UserUpdateRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        userMapper.updateUser(user, request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        var roles = roleRepository.findAllById(request.getRoles());
        user.setRoles(new HashSet<>(roles));

        return userMapper.toUserResponse(userRepository.save(user));
    }

    @PreAuthorize("returnObject.username == authentication.name")
    public ChangePasswordResponse changePassword(String userId, ChangePasswordRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new AppException(ErrorCode.INVALID_OLD_PASSWORD);
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        return ChangePasswordResponse.builder()
                .success(true)
                .build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(String userId){
        userRepository.deleteById(userId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<UserResponse> getUsers() {
        return userRepository.findAll().stream()
                .map(userMapper::toUserResponse)
                .toList();
    }

    @PreAuthorize("hasRole('ADMIN')")
    public UserOnlineStatusResponse isOnline(@PathVariable("id") String userId) {
        Boolean isOnline = redisTemplate.hasKey("ONLINE_USER_" + userId);


        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));


        return UserOnlineStatusResponse.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .isActive(Boolean.TRUE.equals(isOnline)) // isActive từ Redis
                .build();
    }


//    private boolean isActive(Duration activeDuration, User user) {
//        if (user.getLastActiveAt() == null) return false;
//        return user.getLastActiveAt().isAfter(LocalDateTime.now().minus(activeDuration));
//    }


    public UserResponse getMyInfo(){
        var context = SecurityContextHolder.getContext();
        String name = context.getAuthentication().getName();

        User user = userRepository.findByUsername(name).orElseThrow(
                () -> new AppException(ErrorCode.USER_NOT_EXISTED));

        return userMapper.toUserResponse(user);
    }

    @PostAuthorize("returnObject.username == authentication.name or hasRole('ADMIN')")
    public UserResponse getUser(String id){
        return userMapper.toUserResponse(userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED)));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public UserResponse blockUser(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        if (user.isBlocked()) {
            throw new AppException(ErrorCode.USER_ALREADY_BLOCKED);
        }

        user.setBlocked(true);
        userRepository.save(user);

        return userMapper.toUserResponse(user);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public UserResponse unblockUser(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        if (!user.isBlocked()) {
            throw new AppException(ErrorCode.USER_ALREADY_UNBLOCKED);
        }

        user.setBlocked(false);
        userRepository.save(user);

        return userMapper.toUserResponse(user);
    }
}

