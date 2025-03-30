package com.tuandanh.profileService.service;

import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.entity.Friendship;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.enums.FriendStatus;
import com.tuandanh.profileService.exception.AppException;
import com.tuandanh.profileService.exception.ErrorCode;
import com.tuandanh.profileService.mapper.UserProfileMapper;
import com.tuandanh.profileService.repository.FriendshipRepository;
import com.tuandanh.profileService.repository.UserProfileRepository;
import com.tuandanh.profileService.service.redis.RedisService;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class BlockService {
    UserProfileRepository userProfileRepository;
    RedisService redisService;
    UserProfileMapper userProfileMapper;
    FriendshipRepository friendshipRepository;

    private String USER_ID = "userId";

    public String getUserId(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        return jwt.getClaim(USER_ID);
    }

    @Transactional
    public void blockProfile(String blockingId, Authentication authentication) {
        String userId = getUserId(authentication);
        String profileId = redisService.getActiveProfile(userId);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        UserProfile userProfile = userProfileRepository.findById(blockingId).orElseThrow(
                () -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

        if (userProfile.getUserId().equals(userId)) {
            throw new AppException(ErrorCode.CANNOT_BLOCK_OWN_PROFILE);
        }

        // Kiểm tra nếu đã blocking rồi
        boolean isBlocking = userProfileRepository.isBlocking(profileId, blockingId) > 0;

        if (isBlocking) {
            throw new AppException(ErrorCode.ALREADY_BLOCKING);
        }
        log.info("User '{}' is attempting to block '{}'", profileId, blockingId);

        Optional<Friendship> friendshipOpt1 = friendshipRepository.findBySenderIdAndReceiverId(profileId, blockingId);
        Optional<Friendship> friendshipOpt2 = friendshipRepository.findBySenderIdAndReceiverId(blockingId, profileId);

        // Cập nhật trạng thái BLOCKED nếu có quan hệ bạn bè
        boolean updated = false;
        if (friendshipOpt1.isPresent()) {
            Friendship friendship = friendshipOpt1.get();
            friendship.setStatus(FriendStatus.BLOCKED);
            friendshipRepository.save(friendship); // 🔥 Lưu trạng thái vào DB
            updated = true;
        }
        if (friendshipOpt2.isPresent()) {
            Friendship friendship = friendshipOpt2.get();
            friendship.setStatus(FriendStatus.BLOCKED);
            friendshipRepository.save(friendship); // 🔥 Lưu trạng thái vào DB
            updated = true;
        }

        if (updated) {
            log.info("Friendship status updated to BLOCKED between '{}' and '{}'", profileId, blockingId);
        }


        userProfileRepository.blockProfile(profileId, blockingId);

        userProfileRepository.unfollowProfile(profileId, blockingId);
        userProfileRepository.unfollowProfile(blockingId, profileId);
        userProfileRepository.removeFriend(profileId, blockingId);
    }

    @Transactional
    public void unblockProfile(String blockedId, Authentication authentication) {
        String userId = getUserId(authentication);
        String profileId = redisService.getActiveProfile(userId);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        // Kiểm tra profile có tồn tại không
        boolean exists = userProfileRepository.existsById(blockedId);
        if (!exists) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        // Kiểm tra xem có đang block không trước khi unblock
        boolean isBlocking = userProfileRepository.isBlocking(profileId, blockedId) > 0;
        if (!isBlocking) {
            throw new AppException(ErrorCode.NOT_BLOCKING_YET);
        }

        // Xóa trạng thái block
        userProfileRepository.unblockProfile(profileId, blockedId);

        log.info("User '{}' has unblocked '{}'", profileId, blockedId);
    }

    public boolean isBlocked(String targetProfileId, Authentication authentication) {
        String userId = getUserId(authentication);
        String profileId = redisService.getActiveProfile(userId);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        log.info("count for block relationship : " + userProfileRepository.isBlocking(profileId, targetProfileId));
        // Kiểm tra xem profileId có block targetProfileId không
        boolean isBlocked = userProfileRepository.isBlocking(profileId, targetProfileId) > 0;

        log.info("User '{}' checking block status of '{}': {}", profileId, targetProfileId, isBlocked);
        return isBlocked;
    }

    public List<ProfileResponse> getBlockedProfiles(Authentication authentication) {
        String userId = getUserId(authentication);
        String profileId = redisService.getActiveProfile(userId);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        // Lấy danh sách profile đã block
        List<UserProfile> blockedProfiles = userProfileRepository.findBlockedProfiles(profileId);

        log.info("User '{}' fetched blocked list: {} users", profileId, blockedProfiles.size());

        return blockedProfiles.stream()
                .map(userProfileMapper::toProfileResponse)
                .toList();
    }

    public boolean canAccessProfile(String targetProfileId, Authentication authentication) {
        String userId = getUserId(authentication);
        String profileId = redisService.getActiveProfile(userId);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        log.info("count for block relationship : " + userProfileRepository.isBlocking(profileId, targetProfileId));
        // Kiểm tra xem targetProfileId có block profileId không
        boolean isBlockedByTarget = userProfileRepository.isBlocking(targetProfileId, profileId) > 0;

        log.info("User '{}' checking access to '{}': {}", profileId, targetProfileId, !isBlockedByTarget);
        return !isBlockedByTarget;
    }



}
