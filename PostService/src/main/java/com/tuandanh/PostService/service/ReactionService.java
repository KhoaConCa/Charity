package com.tuandanh.PostService.service;

import com.tuandanh.PostService.dto.PageResponse;
import com.tuandanh.PostService.dto.request.ReactionCreationRequest;
import com.tuandanh.PostService.dto.request.ReactionDeletionRequest;
import com.tuandanh.PostService.dto.response.PostResponse;
import com.tuandanh.PostService.dto.response.ReactionResponse;
import com.tuandanh.PostService.entity.Post;
import com.tuandanh.PostService.entity.Reaction;
import com.tuandanh.PostService.enums.ReactionType;
import com.tuandanh.PostService.exception.AppException;
import com.tuandanh.PostService.exception.ErrorCode;
import com.tuandanh.PostService.mapper.ReactionMapper;
import com.tuandanh.PostService.repository.PostRepository;
import com.tuandanh.PostService.repository.ReactionRepository;
import com.tuandanh.PostService.repository.httpClient.UserProfileClient;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ReactionService {
    ReactionRepository reactionRepository;
    PostRepository postRepository;
    ReactionMapper reactionMapper;
    UserProfileClient userProfileClient;

    public ReactionResponse reactToPost(ReactionCreationRequest request, Authentication authentication) {
        String profileId = getProfileIdFromAuthentication(authentication);
        String postId = request.getPostId();
        ReactionType newType = request.getReactionType();

        // Check post exists
        if (!postRepository.existsById(postId)) {
            throw new AppException(ErrorCode.POST_NOT_FOUND);
        }

        // Check if user has already reacted
        Reaction existingReaction = reactionRepository.findByPostIdAndProfileId(postId, profileId);

        if (existingReaction == null) {
            // Create new reaction
            Reaction newReaction = new Reaction();
            newReaction.setPostId(postId);
            newReaction.setProfileId(profileId);
            newReaction.setReactionType(newType);
            newReaction.setCreatedAt(LocalDateTime.now());

            return reactionMapper.toReactionResponse(reactionRepository.save(newReaction));
        }

        if (existingReaction.getReactionType() == newType) {
            // Toggle off (remove)
            reactionRepository.delete(existingReaction);
            // Return a Response that indicates the reaction was removed
            return ReactionResponse.builder()
                    .postId(postId)
                    .profileId(profileId)
                    .reactionType(null) // or maybe keep the old one if needed
                    .action("REMOVED") // you can add a custom field to indicate this
                    .build();
        }

        // Update type
        existingReaction.setReactionType(newType);
        return reactionMapper.toReactionResponse(reactionRepository.save(existingReaction));
    }


    private String getProfileIdFromAuthentication(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String USER_ID = "userId";
        String userId = jwt.getClaimAsString(USER_ID);

        return userProfileClient.getActiveProfile(userId).getResult();
    }

    public PageResponse<ReactionResponse> getReactionsByPost(String postId, int size, int page) {
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = reactionRepository.findAllByPostId(postId, pageable);

        return PageResponse.<ReactionResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream().map(reactionMapper::toReactionResponse).toList())
                .build();
    }

    public long getCountReactionsByPost(String postId) {
        return reactionRepository.countByPostId(postId);
    }


    public Map<ReactionType, Long> getReactionSummary(String postId) {
        List<Reaction> reactions = reactionRepository.findAllByPostId(postId);
        return reactions.stream()
                .collect(Collectors.groupingBy(Reaction::getReactionType, Collectors.counting()));
    }

    public ReactionType getUserReaction(String postId, String profileId) {
        Reaction reaction = reactionRepository.findByPostIdAndProfileId(postId, profileId);
        return reaction != null ? reaction.getReactionType() : null;
    }


    //---------------ADMIN---------------
    @PreAuthorize("hasRole('ADMIN')")
    public void removeAllReactionsByPost(String postId) {
        reactionRepository.deleteAllByPostId(postId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void removeAllReactionsByProfile(String profileId) {
        reactionRepository.deleteAllByProfileId(profileId);
    }

    //-----------------ANALYTICS---------------
//    public List<String> getTopPostsByReaction(ReactionType type) {
//        return reactionRepository.findTopPostIdsByReactionType(type, PageRequest.of(0, 10));
//    }




}
