package com.tuandanh.profileService.service;

import com.tuandanh.profileService.dto.request.FollowRequest;
import com.tuandanh.profileService.dto.response.FollowResponse;
import com.tuandanh.profileService.entity.Friendship;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.exception.AppException;
import com.tuandanh.profileService.exception.ErrorCode;
import com.tuandanh.profileService.mapper.UserProfileMapper;
import com.tuandanh.profileService.repository.FriendshipRepository;
import com.tuandanh.profileService.repository.UserProfileRepository;
import com.tuandanh.profileService.service.aws3.S3Service;
import com.tuandanh.profileService.service.redis.RedisService;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FollowService {
    UserProfileRepository userProfileRepository;
    RedisService redisService;
    BlockService blockService;
    private String USER_ID = "userId";


    public List<UserProfile> getFollowingProfiles(String profileId, Authentication authentication) {
        if (profileId.equals("me")) {
            String userId = getUserId(authentication);
            profileId = redisService.getActiveProfile(userId);

            if (profileId == null || !userProfileRepository.existsById(profileId)) {
                throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
            }
        }

        return userProfileRepository.findFollowingProfiles(profileId);
    }



    @Transactional
    public FollowResponse followProfile(FollowRequest followRequest, Authentication authentication) {
        String userId = getUserId(authentication);
        String profileId = redisService.getActiveProfile(userId);

        String followingId = followRequest.getProfileId();

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        UserProfile userProfile = userProfileRepository.findById(followingId).orElseThrow(
                () -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

        if (userProfile.getUserId().equals(userId)) {
            throw new AppException(ErrorCode.CANNOT_FOLLOW_OWN_PROFILE);
        }

        // 🔥 Kiểm tra nếu block nhau thì không được follow
        if (blockService.isBlocked(followingId, authentication)
                || !blockService.canAccessProfile(followingId, authentication)) {
            throw new AppException(ErrorCode.CANNOT_FOLLOW_DUE_TO_BLOCK);
        }

        // Kiểm tra nếu đã follow rồi
        boolean isFollowing = userProfileRepository.isFollowing(profileId, followingId) > 0;

        if (isFollowing) {
            throw new AppException(ErrorCode.ALREADY_FOLLOWING);
        }
        log.info("User '{}' is attempting to follow '{}'", profileId, followingId);

        userProfileRepository.followProfile(profileId, followingId);

        // Kiểm tra lại trong database xem đã follow chưa
        boolean afterFollow = userProfileRepository.isFollowing(profileId, followingId) > 0;
        log.info("Follow status after operation: {}", afterFollow ? "Success" : "Failed");

        return FollowResponse.builder()
                .result("follow successfully")
                .build();
    }

    @Transactional
    public void unfollowProfile(String followingId, Authentication authentication) {
        String userId = getUserId(authentication);
        String profileId = redisService.getActiveProfile(userId);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        // Kiểm tra profile cần unfollow có tồn tại không
        boolean exists = userProfileRepository.existsById(followingId);
        if (!exists) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        // Kiểm tra xem có đang follow không trước khi unfollow
        boolean isFollowing = userProfileRepository.isFollowing(profileId, followingId) > 0;
        if (!isFollowing) {
            throw new AppException(ErrorCode.NOT_FOLLOWING_YET);
        }

        userProfileRepository.unfollowProfile(profileId, followingId);
    }


    public List<UserProfile> getFollowers(@RequestParam(required = false) String profileId, Authentication authentication) {
        if (profileId.equals("me")) {
            String userId = getUserId(authentication);
            profileId = redisService.getActiveProfile(userId);

            if (profileId == null) {
                throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
            }
        }

        return userProfileRepository.findFollowers(profileId);
    }

    public String getUserId(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        return jwt.getClaim(USER_ID);
    }
}
