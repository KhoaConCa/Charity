package com.tuandanh.PostService.mapper;

import com.tuandanh.PostService.dto.response.ReactionResponse;
import com.tuandanh.PostService.entity.Reaction;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface ReactionMapper {
    ReactionResponse toReactionResponse(Reaction reaction);
}
