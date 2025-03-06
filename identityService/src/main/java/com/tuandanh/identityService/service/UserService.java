package com.tuandanh.identityService.service;

import com.tuandanh.identityService.dto.request.UserCreationRequest;
import com.tuandanh.identityService.dto.request.UserUpdateRequest;
import com.tuandanh.identityService.dto.response.UserResponse;
import com.tuandanh.identityService.entity.User;
import com.tuandanh.identityService.exception.AppException;
import com.tuandanh.identityService.exception.ErrorCode;
import com.tuandanh.identityService.mapper.UserMapper;
import com.tuandanh.identityService.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserService {
    UserRepository userRepository;
    UserMapper userMapper;
    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

    public UserResponse createUser(UserCreationRequest request){
        if (userRepository.existsByUsername(request.getUsername()))
            throw new AppException(ErrorCode.USER_EXISTED);

        User user = userMapper.toUser(request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        return userMapper.toUserResponse(userRepository.save(user));
    }

    public UserResponse updateUser(String userId, UserUpdateRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        userMapper.updateUser(user, request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        return userMapper.toUserResponse(userRepository.save(user));
    }

    public void deleteUser(String userId){
        userRepository.deleteById(userId);
    }

    public List<UserResponse> getUsers(){
        return userRepository.findAll().stream()
                .map(userMapper::toUserResponse).toList();
    }

    public UserResponse getUser(String id){
        return userMapper.toUserResponse(userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED)));
    }

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
