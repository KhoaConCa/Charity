package com.tuandanh.profileService.service;

import com.tuandanh.event.dto.FileMetadataConfirmRequest;
import com.tuandanh.profileService.dto.request.AvatarUploadConfirmRequest;
import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.request.ProfileUpdateRequest;
import com.tuandanh.profileService.dto.request.UploadFileRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.dto.response.UploadFileResponse;
import com.tuandanh.profileService.entity.UserProfile;
import com.tuandanh.profileService.enums.FileType;
import com.tuandanh.profileService.exception.AppException;
import com.tuandanh.profileService.exception.ErrorCode;
import com.tuandanh.profileService.mapper.UserProfileMapper;
import com.tuandanh.profileService.repository.UserProfileRepository;
import com.tuandanh.profileService.repository.httpClient.FileClient;
import com.tuandanh.profileService.service.aws3.S3Service;
import com.tuandanh.profileService.service.redis.RedisService;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserProfileService {
    UserProfileRepository userProfileRepository;
    UserProfileMapper userProfileMapper;
    S3Service s3Service;
    RedisService redisService;
    FileClient fileClient;
    KafkaTemplate<String, FileMetadataConfirmRequest> kafkaTemplate;

    // service/ProfileService.java
    public List<ProfileResponse> getProfilesByUserIds(List<String> userIds) {
        List<UserProfile> profiles = userProfileRepository.findByUserIdIn(userIds);
        return profiles.stream().map(userProfileMapper::toProfileResponse).toList();
    }


    public List<UserProfile> searchProfilesByUsername(String username) {
        return userProfileRepository.findByUsernameContaining(username);
    }

    public String getActiveProfile(String userId){
        return redisService.getActiveProfile(userId);
    }


    public void setActiveProfile(String profileId, Authentication authentication){
        String userId = getUserId(authentication);

        // Kiểm tra profileId có tồn tại không
        boolean exists = userProfileRepository.existsById(profileId);
        if (!exists) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        redisService.setActiveProfile(userId, profileId);

    }

    public String getUserId(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String USER_ID = "userId";
        return jwt.getClaim(USER_ID);
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
    public void updateAvatarVersion2(String profileId, AvatarUploadConfirmRequest avatarUploadConfirmRequest) {
        // Validate file URL là của S3 và đúng định dạng
        if (!avatarUploadConfirmRequest.getFileUrl().contains(".s3.amazonaws.com")) {
            throw new AppException(ErrorCode.INVALID_URL_AWS3);
        }

        // Cập nhật avatar URL vào hồ sơ người dùng
        UserProfile profile = userProfileRepository.findByProfileId(profileId)
                        .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

        profile.setAvatarUrl(avatarUploadConfirmRequest.getFileUrl());
        userProfileRepository.save(profile);

        String fileUrl = avatarUploadConfirmRequest.getFileUrl();

        FileMetadataConfirmRequest event = new FileMetadataConfirmRequest(
                fileUrl.substring(fileUrl.lastIndexOf("/") + 1), // fileName
                fileUrl,
                FileType.AVATAR,
                profileId,
                null,
                "image/jpeg", // nếu bạn có
                LocalDateTime.now()
        );

        kafkaTemplate.send(profile.getProfileId(), event);
    }


    @Transactional
    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
    public String updateAvatar(String profileId, MultipartFile avatarFile) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

//        // Xóa avatar cũ nếu có
//        Optional.ofNullable(userProfile.getAvatarUrl()).ifPresent(fileClient::deleteFile);


        // Gửi request upload file
        String newAvatarUrl = fileClient.uploadFile(avatarFile, profileId, FileType.AVATAR).getResult();


        // Cập nhật avatar mới
        userProfile.setAvatarUrl(newAvatarUrl);
        userProfileRepository.save(userProfile);

        return newAvatarUrl;
    }

    public ProfileResponse createProfileJson(ProfileCreationRequest profileCreationRequest) {
        UserProfile userProfile = userProfileMapper.toUserProfile(profileCreationRequest);

        return userProfileMapper.toProfileResponse(userProfileRepository.save(userProfile));
    }

    @Transactional
    public ProfileResponse createProfileVersion1(ProfileCreationRequest request, AvatarUploadConfirmRequest avatarConfirm) {
        // 1. Validate avatar URL nếu có
        if (avatarConfirm != null && avatarConfirm.getFileUrl() != null) {
            validateS3Url(avatarConfirm.getFileUrl());
        }

        // 2. Tạo profile từ request
        UserProfile profile = userProfileMapper.toUserProfile(request);

        // 3. Gán avatar nếu có
        if (avatarConfirm != null && avatarConfirm.getFileUrl() != null) {
            profile.setAvatarUrl(avatarConfirm.getFileUrl());
        }

        // 4. Lưu profile
        userProfileRepository.save(profile);

        // 5. Gửi Kafka event để lưu metadata file (nếu có)
        if (avatarConfirm != null && avatarConfirm.getFileUrl() != null) {
            kafkaTemplate.send("media.file.metadata", new FileMetadataConfirmRequest());
        }

        return userProfileMapper.toProfileResponse(profile);
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
    public ProfileResponse updateProfileVersion1(String profileId, ProfileUpdateRequest request, AvatarUploadConfirmRequest avatarConfirm) {
        // 1. Validate avatar URL nếu có
        if (avatarConfirm != null && avatarConfirm.getFileUrl() != null) {
            validateS3Url(avatarConfirm.getFileUrl());
        }

        // 2. Tìm user
        UserProfile profile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

        // 3. Gán avatar nếu có
        if (avatarConfirm != null && avatarConfirm.getFileUrl() != null) {
            profile.setAvatarUrl(avatarConfirm.getFileUrl());
        }

        // 4. Update các field khác
        userProfileMapper.updateUserProfile(profile, request);
        userProfileRepository.save(profile);

        // 5. Gửi Kafka metadata
        if (avatarConfirm != null && avatarConfirm.getFileUrl() != null) {
            kafkaTemplate.send("media.file.metadata", new FileMetadataConfirmRequest());
        }

        return userProfileMapper.toProfileResponse(profile);
    }

    private void validateS3Url(String fileUrl) {
        if (!fileUrl.contains(".s3.amazonaws.com")) {
            throw new AppException(ErrorCode.INVALID_URL_AWS3);
        }
    }


    @Transactional
    public ProfileResponse createProfile(ProfileCreationRequest profileCreationRequest, MultipartFile avatarFile) {
        // Upload avatar qua fileClient

        String avatarUrl = fileClient.uploadFile(avatarFile, profileCreationRequest.getUserId(),
                FileType.AVATAR).getResult();


        // Tạo UserProfile từ request
        UserProfile userProfile = userProfileMapper.toUserProfile(profileCreationRequest);
        userProfile.setAvatarUrl(avatarUrl);

        // Lưu vào DB
        userProfile = userProfileRepository.save(userProfile);

        return userProfileMapper.toProfileResponse(userProfile);
    }


    @Transactional
    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
    public ProfileResponse updateProfile(String profileId, ProfileUpdateRequest request, MultipartFile avatarFile)
            throws IOException {

        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));

        String avatarUrl = fileClient.uploadFile(avatarFile, profileId, FileType.AVATAR).getResult();
        userProfile.setAvatarUrl(avatarUrl);


        // Cập nhật các thông tin khác từ request
        userProfileMapper.updateUserProfile(userProfile, request);
        userProfile = userProfileRepository.save(userProfile);

        return userProfileMapper.toProfileResponse(userProfile);
    }


    @PreAuthorize("hasRole('ADMIN') or @userProfileService.isProfileOwner(#profileId, authentication)")
    public void deleteProfile(String profileId) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));
        userProfileRepository.delete(userProfile);
    }


    public ProfileResponse getProfileByProfileId(String profileId) {
        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));
        return userProfileMapper.toProfileResponse(userProfile);
    }

    public List<ProfileResponse> getMyProfiles(Authentication authentication) {
        String userId = getUserId(authentication);

        List<UserProfile> userProfiles = userProfileRepository.findByUserId(userId);

        if (userProfiles.isEmpty()) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        return userProfiles.stream()
                .map(userProfileMapper::toProfileResponse)
                .collect(Collectors.toList());
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<ProfileResponse> getAllProfiles() {
        List<UserProfile> userProfiles = userProfileRepository.findAll();

        if (userProfiles.isEmpty()) {
            throw new AppException(ErrorCode.PROFILE_NOT_EXISTED);
        }

        return userProfiles.stream()
                .map(userProfileMapper::toProfileResponse)
                .collect(Collectors.toList());
    }



    public boolean isProfileOwner(String profileId, Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String userId = jwt.getClaim("userId");

        UserProfile userProfile = userProfileRepository.findById(profileId)
                .orElseThrow(() -> new AppException(ErrorCode.PROFILE_NOT_EXISTED));



        boolean result = userProfile.getUserId().equals(userId);

        return result;
    }



}
