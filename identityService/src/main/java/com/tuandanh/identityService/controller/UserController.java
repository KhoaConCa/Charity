package com.tuandanh.identityService.controller;

import com.tuandanh.identityService.dto.ApiResponse;
import com.tuandanh.identityService.dto.request.ChangePasswordRequest;
import com.tuandanh.identityService.dto.request.UserCreationRequest;
import com.tuandanh.identityService.dto.request.UserUpdateRequest;
import com.tuandanh.identityService.dto.response.ChangePasswordResponse;
import com.tuandanh.identityService.dto.response.UserOnlineStatusResponse;
import com.tuandanh.identityService.dto.response.UserResponse;
import com.tuandanh.identityService.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "User Controller", description =
        "Quản lý người dùng, bao gồm tạo, cập nhật, xoá, và các thao tác khác liên quan đến người dùng")
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    UserService userService;

    @Operation(
            summary = "Lấy thông tin cá nhân",
            description = "API trả về thông tin chi tiết của người dùng hiện đang đăng nhập"
    )
    @GetMapping("/myInfo")
    ApiResponse<UserResponse> getMyInfo(){
        return ApiResponse.<UserResponse>builder()
                .result(userService.getMyInfo())
                .build();
    }

    @Operation(
            summary = "Tạo người dùng mới",
            description = "API dùng để tạo một người dùng mới với các thông tin cung cấp trong request body"
    )
    @PostMapping("/registration")
    public ApiResponse<UserResponse> createUser(@RequestBody @Valid UserCreationRequest request){
        return ApiResponse.<UserResponse>builder()
                .result(userService.createUser(request))
                .build();
    }

    @Operation(
            summary = "Lấy danh sách người dùng",
            description = "API trả về danh sách tất cả người dùng hiện có trong hệ thống"
    )
    @GetMapping
    public ApiResponse<List<UserResponse>> getUsers(){
        return ApiResponse.<List<UserResponse>>builder()
                .result(userService.getUsers())
                .build();
    }

    @Operation(
            summary = "Lấy thông tin người dùng theo ID",
            description = "API trả về thông tin chi tiết của người dùng theo ID cung cấp"
    )
    @GetMapping("/{userId}")
    public ApiResponse<UserResponse> getUser(@PathVariable("userId") String userId){
        return ApiResponse.<UserResponse>builder()
                .result(userService.getUser(userId))
                .build();
    }

    @Operation(
            summary = "Cập nhật thông tin người dùng",
            description = "API cập nhật thông tin của người dùng theo ID cung cấp, dựa trên dữ liệu request body"
    )
    @PutMapping("/{userId}")
    public ApiResponse<UserResponse> updateUser(@PathVariable String userId, @RequestBody UserUpdateRequest request){
        return ApiResponse.<UserResponse>builder()
                .result(userService.updateUser(userId, request))
                .build();
    }

    @Operation(
            summary = "Xoá người dùng",
            description = "API dùng để xoá người dùng theo ID cung cấp"
    )
    @DeleteMapping("/{userId}")
    public ApiResponse<String> deleteUser(@PathVariable String userId){
        userService.deleteUser(userId);
        return ApiResponse.<String>builder()
                .result("User has been deleted")
                .build();
    }

    @Operation(
            summary = "Khoá người dùng",
            description = "API dùng để khoá tài khoản người dùng theo ID cung cấp, ngăn chặn quyền truy cập hệ thống"
    )
    @PatchMapping("/{userId}/block")
    public ApiResponse<UserResponse> blockUser(@PathVariable String userId) {
        return ApiResponse.<UserResponse>builder()
                .result(userService.blockUser(userId))
                .build();
    }

    @Operation(
            summary = "Mở khoá người dùng",
            description = "API dùng để mở khoá tài khoản người dùng theo ID đã bị khoá trước đó"
    )
    @PatchMapping("/{userId}/unblock")
    public ApiResponse<UserResponse> unblockUser(@PathVariable String userId) {
        return ApiResponse.<UserResponse>builder()
                .result(userService.unblockUser(userId))
                .build();
    }

    @Operation(
            summary = "Đổi mật khẩu người dùng",
            description = "API dùng để thay đổi mật khẩu cho người dùng theo ID cung cấp, yêu cầu nhập mật khẩu cũ và mật khẩu mới"
    )
    @PutMapping("/{userId}/changepassword")
    public ApiResponse<ChangePasswordResponse> changePassword(@PathVariable String userId,
                                                              @RequestBody @Valid ChangePasswordRequest request){
        return ApiResponse.<ChangePasswordResponse>builder()
                .result(userService.changePassword(userId, request))
                .build();
    }

    @Operation(
            summary = "Kiểm tra trạng thái online của người dùng",
            description = "API kiểm tra xem người dùng theo ID cung cấp hiện có đang online hay không"
    )
    @GetMapping("/{userId}/is-online")
    public ApiResponse<UserOnlineStatusResponse> checkUserOnlineStatus(@PathVariable String userId){
        return ApiResponse.<UserOnlineStatusResponse>builder()
                .result(userService.isOnline(userId))
                .build();
    }
}
