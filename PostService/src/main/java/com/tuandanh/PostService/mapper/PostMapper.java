package com.tuandanh.PostService.mapper;

import com.tuandanh.PostService.dto.response.PostResponse;
import com.tuandanh.PostService.entity.Post;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface PostMapper {
    PostResponse toPostResponse(Post post);
}
