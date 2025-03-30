package com.tuandanh.profileService.controller;

import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.FriendshipRequest;
import com.tuandanh.profileService.dto.response.FriendshipResponse;
import com.tuandanh.profileService.entity.Friendship;
import com.tuandanh.profileService.enums.FriendStatus;
import com.tuandanh.profileService.service.FriendshipService;
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
public class FriendShipController {
    FriendshipService friendshipService;

    @GetMapping("/status/{targetProfileId}")
    public ApiResponse<FriendStatus> getFriendStatus(@PathVariable String targetProfileId, Authentication authentication) {
        FriendStatus status = friendshipService.getFriendshipStatus(targetProfileId, authentication);

        return ApiResponse.<FriendStatus>builder()
                .result(status)
                .build();
    }

    @GetMapping("/requests")
    public ApiResponse<List<FriendshipResponse>> getFriendRequests(Authentication authentication) {
        List<FriendshipResponse> friendRequests = friendshipService.getAllFriendshipRequestsByProfileId(authentication);

        return ApiResponse.<List<FriendshipResponse>>builder()
                .result(friendRequests)
                .build();
    }

    @GetMapping
    public ApiResponse<List<FriendshipResponse>> getFriends(Authentication authentication) {
        List<FriendshipResponse> friendshipResponses = friendshipService.getAllFriendshipsByProfileId(authentication);

        return ApiResponse.<List<FriendshipResponse>>builder()
                .result(friendshipResponses)
                .build();
    }

    @PostMapping("/cancel-request")
    public ApiResponse<FriendshipResponse> cancelRequest(@RequestBody FriendshipRequest friendshipRequest) {
        FriendshipResponse friendshipResponse = friendshipService.cancelFriendRequest(friendshipRequest);

        return ApiResponse.<FriendshipResponse>builder()
                .result(friendshipResponse)
                .build();
    }

    @DeleteMapping("/remove/{requestId}")
    public ApiResponse<String> removeFriend(@PathVariable String requestId){
        String response = friendshipService.removeFriend(requestId);

        return ApiResponse.<String>builder()
                .result(response)
                .build();
    }

    @PostMapping("/request")
    public ApiResponse<FriendshipResponse> requestFriendship(@RequestBody FriendshipRequest request,
                                                             Authentication authentication) {
        FriendshipResponse friendshipResponse = friendshipService.sendFriendRequest(request, authentication);

        return ApiResponse.<FriendshipResponse>builder()
                .result(friendshipResponse)
                .build();
    }

    @PostMapping("/accept/{requestId}")
    public ApiResponse<FriendshipResponse> acceptFriendship(@PathVariable String requestId, Authentication authentication) {
        FriendshipResponse friendshipResponse = friendshipService.acceptFriendRequest(requestId, authentication);

        return ApiResponse.<FriendshipResponse>builder()
                .result(friendshipResponse)
                .build();
    }

    @PostMapping("/decline/{requestId}")
    public ApiResponse<FriendshipResponse> declineFriendship(@PathVariable String requestId, Authentication authentication) {
        FriendshipResponse friendshipResponse = friendshipService.declineFriendRequest(requestId, authentication);

        return ApiResponse.<FriendshipResponse>builder()
                .result(friendshipResponse)
                .build();
    }
}
