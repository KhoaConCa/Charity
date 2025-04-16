package com.tuandanh.PostService.service;

import com.tuandanh.PostService.dto.response.ReactionResponse;
import com.tuandanh.PostService.entity.Post;
import com.tuandanh.PostService.entity.Reaction;
import com.tuandanh.PostService.enums.ReactionType;
import com.tuandanh.PostService.exception.AppException;
import com.tuandanh.PostService.exception.ErrorCode;
import com.tuandanh.PostService.repository.PostRepository;
import com.tuandanh.PostService.repository.ReactionRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ReactionService {
    ReactionRepository reactionRepository;
    PostRepository postRepository;

    public ReactionResponse addReaction(String postId, ReactionType reactionType, Authentication authentication) {

        String profileId = getProfileIdFromAuthorization(authorization);

        // Lấy bài viết
        Post post = postRepository.findById(postId).orElseThrow(() -> new AppException(ErrorCode.POST_NOT_FOUND));

        // Kiểm tra xem người dùng đã react chưa
        Reaction existingReaction = reactionRepository.findByPostIdAndProfileId(postId, profileId);
        if (existingReaction != null) {
            throw new AppException(ErrorCode.REACTION_ALREADY_EXISTS);
        }

        // Tạo reaction mới
        Reaction reaction = new Reaction();
        reaction.setPostId(postId);
        reaction.setProfileId(profileId);
        reaction.setReactionType(reactionType);
        reaction.setCreatedAt(LocalDateTime.now());

        // Lưu reaction vào cơ sở dữ liệu
        return reactionRepository.save(reaction);
    }
}
