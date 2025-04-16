package com.tuandanh.PostService.mapper;

import com.tuandanh.PostService.dto.request.CommentCreationRequest;
import com.tuandanh.PostService.dto.response.CommentResponse;
import com.tuandanh.PostService.entity.Comment;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface CommentMapper {
    CommentResponse toCommentResponse(Comment comment);
    Comment toComment(CommentCreationRequest commentCreationRequest);
}
