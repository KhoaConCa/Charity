package com.tuandanh.profileService.service;

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
