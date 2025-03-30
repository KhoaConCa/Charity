package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.FriendshipRequest;
import com.tuandanh.profileService.dto.response.FriendshipResponse;
import com.tuandanh.profileService.entity.Friendship;
import com.tuandanh.profileService.enums.FriendStatus;
import com.tuandanh.profileService.service.FriendshipService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/friends")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Friendship Controller", description = "Quản lý quan hệ bạn bè")
public class FriendShipController {
    FriendshipService friendshipService;

    @Operation(summary = "Lấy trạng thái bạn bè", description = "API kiểm tra trạng thái bạn bè giữa người dùng hiện tại và một hồ sơ khác")
    @GetMapping("/status/{targetProfileId}")
    public ApiResponse<FriendStatus> getFriendStatus(
            @PathVariable String targetProfileId,
            @Parameter(hidden = true) Authentication authentication) {
        FriendStatus status = friendshipService.getFriendshipStatus(targetProfileId, authentication);
        return ApiResponse.<FriendStatus>builder().result(status).build();
    }

    @Operation(summary = "Lấy danh sách lời mời kết bạn", description = "API lấy danh sách tất cả lời mời kết bạn của người dùng hiện tại")
    @GetMapping("/requests")
    public ApiResponse<List<FriendshipResponse>> getFriendRequests(
            @Parameter(hidden = true) Authentication authentication) {
        List<FriendshipResponse> friendRequests = friendshipService.getAllFriendshipRequestsByProfileId(authentication);
        return ApiResponse.<List<FriendshipResponse>>builder().result(friendRequests).build();
    }

    @Operation(summary = "Lấy danh sách bạn bè", description = "API lấy danh sách tất cả bạn bè của người dùng hiện tại")
    @GetMapping
    public ApiResponse<List<FriendshipResponse>> getFriends(
            @Parameter(hidden = true) Authentication authentication) {
        List<FriendshipResponse> friendshipResponses = friendshipService.getAllFriendshipsByProfileId(authentication);
        return ApiResponse.<List<FriendshipResponse>>builder().result(friendshipResponses).build();
    }

    @Operation(summary = "Hủy lời mời kết bạn", description = "API hủy một yêu cầu kết bạn đã gửi")
    @PostMapping("/cancel-request")
    public ApiResponse<FriendshipResponse> cancelRequest(@RequestBody FriendshipRequest friendshipRequest) {
        FriendshipResponse friendshipResponse = friendshipService.cancelFriendRequest(friendshipRequest);
        return ApiResponse.<FriendshipResponse>builder().result(friendshipResponse).build();
    }

    @Operation(summary = "Xóa bạn bè", description = "API xóa một người bạn khỏi danh sách bạn bè")
    @DeleteMapping("/remove/{requestId}")
    public ApiResponse<String> removeFriend(@PathVariable String requestId) {
        String response = friendshipService.removeFriend(requestId);
        return ApiResponse.<String>builder().result(response).build();
    }

    @Operation(summary = "Gửi lời mời kết bạn", description = "API gửi một lời mời kết bạn đến một người dùng khác")
    @PostMapping("/request")
    public ApiResponse<FriendshipResponse> requestFriendship(
            @RequestBody FriendshipRequest request,
            @Parameter(hidden = true) Authentication authentication) {
        FriendshipResponse friendshipResponse = friendshipService.sendFriendRequest(request, authentication);
        return ApiResponse.<FriendshipResponse>builder().result(friendshipResponse).build();
    }

    @Operation(summary = "Chấp nhận lời mời kết bạn", description = "API chấp nhận một lời mời kết bạn từ người dùng khác")
    @PostMapping("/accept/{requestId}")
    public ApiResponse<FriendshipResponse> acceptFriendship(
            @PathVariable String requestId,
            @Parameter(hidden = true) Authentication authentication) {
        FriendshipResponse friendshipResponse = friendshipService.acceptFriendRequest(requestId, authentication);
        return ApiResponse.<FriendshipResponse>builder().result(friendshipResponse).build();
    }

    @Operation(summary = "Từ chối lời mời kết bạn", description = "API từ chối một lời mời kết bạn từ người dùng khác")
    @PostMapping("/decline/{requestId}")
    public ApiResponse<FriendshipResponse> declineFriendship(
            @PathVariable String requestId,
            @Parameter(hidden = true) Authentication authentication) {
        FriendshipResponse friendshipResponse = friendshipService.declineFriendRequest(requestId, authentication);
        return ApiResponse.<FriendshipResponse>builder().result(friendshipResponse).build();
    }
}

