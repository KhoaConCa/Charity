package com.tuandanh.profileService.mapper;

import com.tuandanh.profileService.dto.request.ProfileCreationRequest;
import com.tuandanh.profileService.dto.request.ProfileUpdateRequest;
import com.tuandanh.profileService.dto.response.ProfileResponse;
import com.tuandanh.profileService.entity.UserProfile;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    comments = "version: 1.5.5.Final, compiler: Eclipse JDT (IDE) 3.42.0.z20250331-1358, environment: Java 21.0.6 (Eclipse Adoptium)"
)
@Component
public class UserProfileMapperImpl implements UserProfileMapper {

    @Override
    public UserProfile toUserProfile(ProfileCreationRequest profileCreationRequest) {
        if ( profileCreationRequest == null ) {
            return null;
        }

        UserProfile.UserProfileBuilder userProfile = UserProfile.builder();

        userProfile.firstName( profileCreationRequest.getFirstName() );
        userProfile.lastName( profileCreationRequest.getLastName() );
        userProfile.location( profileCreationRequest.getLocation() );
        userProfile.userId( profileCreationRequest.getUserId() );
        userProfile.username( profileCreationRequest.getUsername() );

        return userProfile.build();
    }

    @Override
    public ProfileResponse toProfileResponse(UserProfile userProfile) {
        if ( userProfile == null ) {
            return null;
        }

        ProfileResponse.ProfileResponseBuilder profileResponse = ProfileResponse.builder();

        profileResponse.avatarUrl( userProfile.getAvatarUrl() );
        profileResponse.createdAt( userProfile.getCreatedAt() );
        profileResponse.firstName( userProfile.getFirstName() );
        profileResponse.lastName( userProfile.getLastName() );
        profileResponse.location( userProfile.getLocation() );
        profileResponse.profileId( userProfile.getProfileId() );
        profileResponse.updatedAt( userProfile.getUpdatedAt() );
        profileResponse.userId( userProfile.getUserId() );
        profileResponse.username( userProfile.getUsername() );

        return profileResponse.build();
    }

    @Override
    public void updateUserProfile(UserProfile userProfile, ProfileUpdateRequest profileUpdateRequest) {
        if ( profileUpdateRequest == null ) {
            return;
        }

        userProfile.setFirstName( profileUpdateRequest.getFirstName() );
        userProfile.setLastName( profileUpdateRequest.getLastName() );
        userProfile.setLocation( profileUpdateRequest.getLocation() );
        userProfile.setUsername( profileUpdateRequest.getUsername() );
    }
}
