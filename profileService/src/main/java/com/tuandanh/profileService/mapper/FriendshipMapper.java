package com.tuandanh.profileService.mapper;

import com.tuandanh.profileService.dto.response.FriendshipResponse;
import com.tuandanh.profileService.entity.Friendship;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface FriendshipMapper {
    FriendshipResponse toFriendshipResponse(Friendship friendship);
}
