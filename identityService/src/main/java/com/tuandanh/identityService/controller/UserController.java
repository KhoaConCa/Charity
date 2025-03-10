package com.tuandanh.identityService.controller;

import com.tuandanh.identityService.dto.ApiResponse;
import com.tuandanh.identityService.dto.request.ChangePasswordRequest;
import com.tuandanh.identityService.dto.request.UserCreationRequest;
import com.tuandanh.identityService.dto.request.UserUpdateRequest;
import com.tuandanh.identityService.dto.response.ChangePasswordResponse;
import com.tuandanh.identityService.dto.response.UserOnlineStatusResponse;
import com.tuandanh.identityService.dto.response.UserResponse;
import com.tuandanh.identityService.service.UserService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    UserService userService;

    @GetMapping("/myInfo")
    ApiResponse<UserResponse> getMyInfo(){
        return ApiResponse.<UserResponse>builder()
                .result(userService.getMyInfo())
                .build();
    }

    @PostMapping
    public ApiResponse<UserResponse> createUser(@RequestBody @Valid UserCreationRequest request){
        return ApiResponse.<UserResponse>builder()
                .result(userService.createUser(request))
                .build();
    }

    @GetMapping
    public ApiResponse<List<UserResponse>> getUsers(){
        return ApiResponse.<List<UserResponse>>builder()
                .result(userService.getUsers())
                .build();
    }

    @GetMapping("/{userId}")
    public ApiResponse<UserResponse> getUser(@PathVariable("userId") String userId){
        return ApiResponse.<UserResponse>builder()
                .result(userService.getUser(userId))
                .build();
    }

    @PutMapping("/{userId}")
    public ApiResponse<UserResponse> updateUser(@PathVariable String userId, @RequestBody UserUpdateRequest request){
        return ApiResponse.<UserResponse>builder()
                .result(userService.updateUser(userId, request))
                .build();
    }

    @DeleteMapping("/{userId}")
    public ApiResponse<String> deleteUser(@PathVariable String userId){
        userService.deleteUser(userId);
        return ApiResponse.<String>builder()
                .result("User has been deleted")
                .build();
    }

    @PatchMapping("/{userId}/block")
    public ApiResponse<UserResponse> blockUser(@PathVariable String userId) {
        return ApiResponse.<UserResponse>builder()
                .result(userService.blockUser(userId))
                .build();
    }

    @PatchMapping("/{userId}/unblock")
    public ApiResponse<UserResponse> unblockUser(@PathVariable String userId) {
        return ApiResponse.<UserResponse>builder()
                .result(userService.unblockUser(userId))
                .build();
    }

    @PutMapping("/{userId}/changepassword")
    public ApiResponse<ChangePasswordResponse> changePassword(@PathVariable String userId,
                                                              @RequestBody @Valid ChangePasswordRequest request){
        return ApiResponse.<ChangePasswordResponse>builder()
                .result(userService.changePassword(userId, request))
                .build();
    }

    @GetMapping("/{userId}/is-online")
    public ApiResponse<UserOnlineStatusResponse> checkUserOnlineStatus(@PathVariable String userId){
        return ApiResponse.<UserOnlineStatusResponse>builder()
                .result(userService.isOnline(userId))
                .build();
    }
}
