package com.tuandanh.profileService.service;


import com.tuandanh.event.dto.NotificationEvent;
import com.tuandanh.profileService.dto.request.FriendshipRequest;
import com.tuandanh.profileService.dto.response.FriendshipResponse;
import com.tuandanh.profileService.entity.Friendship;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.enums.CHANEL;
import com.tuandanh.profileService.enums.FriendStatus;
import com.tuandanh.profileService.enums.KafkaTopic;
import com.tuandanh.profileService.enums.NotificationType;
import com.tuandanh.profileService.exception.AppException;
import com.tuandanh.profileService.exception.ErrorCode;
import com.tuandanh.profileService.mapper.FriendshipMapper;
import com.tuandanh.profileService.repository.FriendshipRepository;
import com.tuandanh.profileService.repository.UserProfileRepository;
import com.tuandanh.profileService.service.redis.RedisService;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FriendshipService {
    FriendshipRepository friendshipRepository;
    UserProfileRepository userProfileRepository;
    UserProfileService userProfileService;
    RedisService redisService;
    FriendshipMapper friendshipMapper;
    BlockService blockService;
    KafkaTemplate<String, NotificationEvent> kafkaTemplate;
    JwtDecoder jwtDecoder;

    public FriendStatus getFriendshipStatus(String targetProfileId, Authentication authentication) {
        String profileId = getProfileId(authentication);


        if (profileId == null || targetProfileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        return friendshipRepository.findFriendshipStatus(profileId, targetProfileId)
                .orElse(FriendStatus.NONE); // Trả về NONE nếu không có quan hệ nào
    }



    public List<FriendshipResponse> getAllFriendshipsByProfileId(String authorization) {

        String profileId = getProfileIdFromToken(authorization);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        return friendshipRepository.findAllByReceiverIdAndStatus(profileId, FriendStatus.ACCEPTED).stream()
                .map(friendshipMapper::toFriendshipResponse).toList();
    }

    private String getProfileIdFromToken(String authorization) {
        if (StringUtils.isEmpty(authorization) || !authorization.startsWith("Bearer ")) {
            throw new AppException(ErrorCode.INVALID_TOKEN);
        }
        // Lấy token JWT sau "Bearer "
        String token = authorization.substring(7);

        // Giải mã token để lấy profileId (sử dụng thư viện JWT của Spring Security hoặc JWT)
        Jwt jwt = jwtDecoder.decode(token);
        String userId = jwt.getClaim("userId");
        return redisService.getActiveProfile(userId);
    }


    public List<FriendshipResponse> getAllFriendshipRequestsByProfileId(Authentication authentication) {
        String profileId = getProfileId(authentication);

        if (profileId == null) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        return friendshipRepository.findAllByReceiverIdAndStatus(profileId, FriendStatus.PENDING).stream()
                .map(friendshipMapper::toFriendshipResponse).toList();
    }


    @Transactional
    public FriendshipResponse cancelFriendRequest(FriendshipRequest friendshipRequest) {
        String senderId = friendshipRequest.getSenderId();
        String receiverId = friendshipRequest.getReceiverId();
        Optional<Friendship> requestOpt = friendshipRepository.findBySenderIdAndReceiverId(senderId, receiverId);
        if (requestOpt.isEmpty()) throw new AppException(ErrorCode.FRIEND_REQUEST_NOT_FOUND);
        Friendship request = requestOpt.get();
        if (request.getStatus() != FriendStatus.PENDING) throw new AppException(ErrorCode.CANNOT_CANCEL_FRIEND_REQUEST);

        request.setStatus(FriendStatus.CANCELED);

        return friendshipMapper.toFriendshipResponse(friendshipRepository.save(request));
    }

    @Transactional
    public FriendshipResponse sendFriendRequest(FriendshipRequest friendshipRequest, Authentication authentication) {
        String senderId = friendshipRequest.getSenderId();
        String receiverId = friendshipRequest.getReceiverId();

        Optional<Friendship> friendshipOpt1 = friendshipRepository.findBySenderIdAndReceiverId(senderId, receiverId);
        Optional<Friendship> friendshipOpt2 = friendshipRepository.findBySenderIdAndReceiverId(receiverId, senderId);

        // Nếu đã tồn tại yêu cầu trước đó
        if (friendshipOpt1.isPresent()) {
            Friendship existingRequest = friendshipOpt1.get();

            // Nếu trạng thái trước đó là PENDING thì không thể gửi lại
            if (existingRequest.getStatus() == FriendStatus.PENDING) {
                throw new AppException(ErrorCode.ALREADY_SENT_REQUEST_FRIEND);
            }

            // Nếu trạng thái trước đó là CANCELED và REMOVED, cập nhật lại thành PENDING
            if (checkRequestAndStatus(senderId, receiverId, existingRequest))
                return friendshipMapper.toFriendshipResponse(existingRequest);

        }

        // Nếu đã nhận lời mời từ người kia
        if (friendshipOpt2.isPresent()) {
            Friendship existingRequest = friendshipOpt1.get();

            // Nếu trạng thái trước đó là PENDING thì không thể gửi lại
            if (existingRequest.getStatus() == FriendStatus.PENDING) {
                throw new AppException(ErrorCode.REQUEST_FRIEND_ALREADY_RECEIVED);
            }

            // Nếu trạng thái trước đó là CANCELED, cập nhật lại thành PENDING
            if (checkRequestAndStatus(senderId, receiverId, existingRequest))
                return friendshipMapper.toFriendshipResponse(existingRequest);
        }

        // 🔥 Kiểm tra nếu block nhau thì không được follow
        if (blockService.isBlocked(receiverId, authentication)
                || !blockService.canAccessProfile(receiverId, authentication)) {
            throw new AppException(ErrorCode.CANNOT_ADD_FRIEND_DUE_TO_BLOCK);
        }

        // Kiểm tra xem có phải bạn bè không
        boolean alreadyFriends = friendshipOpt1.map(f -> f.getStatus() == FriendStatus.ACCEPTED).orElse(false)
                || friendshipOpt2.map(f -> f.getStatus() == FriendStatus.ACCEPTED).orElse(false);

        if (alreadyFriends) {
            throw new AppException(ErrorCode.ALREADY_FRIENDS);
        }

        // Tạo mới lời mời kết bạn
        Friendship newRequest = Friendship.builder()
                .senderId(senderId)
                .receiverId(receiverId)
                .status(FriendStatus.PENDING)
                .build();

        log.error("friendship : " + newRequest);
        friendshipRepository.save(newRequest);

        UserProfile senderProfile = userProfileRepository.findById(senderId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));
        String avatarUrl = senderProfile.getAvatarUrl();

        Map<String, Object> params = new HashMap<>();
        params.put("senderId", senderId);
        params.put("userId", receiverId);
        params.put("notificationType", NotificationType.FRIEND_REQUEST);
        params.put("avatarUrl", avatarUrl);

        // Gửi thông báo qua Kafka cho receiver (User B) về lời mời kết bạn từ User A
        NotificationEvent notificationEvent = NotificationEvent.builder()
                .chanel(CHANEL.PUSH_NOTIFICATION)
                .recipient(receiverId)  // Người nhận thông báo là receiverId
                .param(params)  // Thêm thông tin động vào template (ví dụ: tên người gửi)
                .subject("Lời mời kết bạn")
                .body("User " + senderId + " đã gửi lời mời kết bạn cho bạn.")
                .build();

        kafkaTemplate.send(KafkaTopic.USER_NEW_FRIEND.getTopic(),notificationEvent);  // Gửi message qua Kafka

        return friendshipMapper.toFriendshipResponse(newRequest);
    }

    private boolean checkRequestAndStatus(String senderId, String receiverId, Friendship existingRequest) {
        if (existingRequest.getStatus() == FriendStatus.CANCELED || existingRequest.getStatus() == FriendStatus.REMOVED
                || existingRequest.getStatus() == FriendStatus.DECLINED) {
            existingRequest.setSenderId(senderId);
            existingRequest.setReceiverId(receiverId);
            existingRequest.setStatus(FriendStatus.PENDING);
            friendshipRepository.save(existingRequest);
            return true;
        }
        return false;
    }

    @Transactional
    public FriendshipResponse acceptFriendRequest(String requestId, Authentication authentication) {
        String profileId = getProfileId(authentication);

        Optional<Friendship> requestOpt = friendshipRepository.findById(requestId);

        log.info("profileId : " + profileId);
        log.info("receivedId : " + requestOpt.get().getReceiverId());

        if(!profileId.equals(requestOpt.get().getReceiverId()))
            throw new AppException(ErrorCode.DONT_HAVE_PERMISSION_TO_ACCEPT);
        
        
        if (requestOpt.isEmpty()) {
            throw new AppException(ErrorCode.FRIEND_REQUEST_NOT_FOUND);
        }
        Friendship request = requestOpt.get();
        if (request.getStatus() != FriendStatus.PENDING) {
            if(request.getStatus() == FriendStatus.ACCEPTED) {
                throw new AppException(ErrorCode.ALREADY_ACCEPTED_REQUEST_FRIEND);
            }
            else{
                if(request.getStatus() == FriendStatus.REMOVED) {
                    throw new AppException(ErrorCode.ALREADY_REMOVED);
                }
                else{
                    if(request.getStatus() == FriendStatus.DECLINED) {
                        throw new AppException(ErrorCode.ALREADY_DECLINED);
                    }
                }
            }
        }

        Friendship friendshipRequest = requestOpt.get();
        String senderId = friendshipRequest.getSenderId();
        String receivedId = friendshipRequest.getReceiverId();


        userProfileRepository.followProfile(senderId, receivedId);
        userProfileRepository.followProfile(receivedId, senderId);
        userProfileRepository.addFriend(senderId, receivedId);

        friendshipRequest.setStatus(FriendStatus.ACCEPTED);


        return friendshipMapper.toFriendshipResponse(friendshipRepository.save(friendshipRequest));
    }

    private String getProfileId(Authentication authentication) {
        String userId = userProfileService.getUserId(authentication);
        return redisService.getActiveProfile(userId);
    }

    @Transactional
    public String removeFriend(String requestId) {
        Optional<Friendship> friendshipOpt = friendshipRepository
                .findById(requestId);

        if (friendshipOpt.isEmpty() || friendshipOpt.get().getStatus() != FriendStatus.ACCEPTED) {
            throw new AppException(ErrorCode.CANNOT_REMOVE_FRIEND_REQUEST);
        }

        Friendship friendship = friendshipOpt.get();
        friendship.setStatus(FriendStatus.REMOVED); // Cập nhật trạng thái
        friendshipRepository.save(friendship);

        String senderId = friendship.getSenderId();
        String receivedId = friendship.getReceiverId();

        userProfileRepository.removeFriend(senderId, receivedId); // Cập nhật Neo4j

        return "Đã hủy kết bạn!";
    }

    @Transactional
    public FriendshipResponse declineFriendRequest(String requestId, Authentication authentication) {
        String profileId = getProfileId(authentication);

        Optional<Friendship> requestOpt = friendshipRepository.findById(requestId);

        log.info("profileId : " + profileId);
        log.info("receivedId : " + requestOpt.get().getReceiverId());

        if(!profileId.equals(requestOpt.get().getReceiverId())) throw new AppException(ErrorCode.DONT_HAVE_PERMISSION_TO_DECLINE);

        if (requestOpt.isEmpty()) {
            throw  new AppException(ErrorCode.FRIEND_REQUEST_NOT_FOUND);
        }
        Friendship request = requestOpt.get();
        if (request.getStatus() != FriendStatus.PENDING) {
            throw  new AppException(ErrorCode.CANNOT_DECLINE_FRIEND_REQUEST);
        }
        request.setStatus(FriendStatus.DECLINED);

        return friendshipMapper.toFriendshipResponse(friendshipRepository.save(request));
    }
}
