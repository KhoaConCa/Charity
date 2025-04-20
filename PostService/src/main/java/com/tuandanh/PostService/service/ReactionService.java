package com.tuandanh.PostService.service;

import com.tuandanh.PostService.dto.PageResponse;
import com.tuandanh.PostService.dto.request.ReactionCreationRequest;
import com.tuandanh.PostService.dto.response.ReactionResponse;
import com.tuandanh.PostService.entity.Reaction;
import com.tuandanh.PostService.enums.ReactionType;
import com.tuandanh.PostService.exception.AppException;
import com.tuandanh.PostService.exception.ErrorCode;
import com.tuandanh.PostService.mapper.ReactionMapper;
import com.tuandanh.PostService.repository.CommentRepository;
import com.tuandanh.PostService.repository.PostRepository;
import com.tuandanh.PostService.repository.ReactionRepository;
import com.tuandanh.PostService.repository.httpClient.UserProfileClient;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
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
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
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
    CommentRepository commentRepository;

    private ReactionResponse handleReaction(
            String targetId,
            String profileId,
            ReactionType newType,
            Function<String, Boolean> existsById,
            BiFunction<String, String, Reaction> findReaction,
            Function<Reaction, Reaction> saveReaction,
            Consumer<Reaction> deleteReaction,
            BiConsumer<Reaction, String> setTargetId // 👈 thêm cái này để set đúng trường postId hoặc commentId
    ) {
        if (!existsById.apply(targetId)) {
            throw new AppException(ErrorCode.ID_NOT_FOUND);
        }

        Reaction existingReaction = findReaction.apply(targetId, profileId);

        if (existingReaction == null) {
            Reaction newReaction = new Reaction();
            newReaction.setCreatedAt(LocalDateTime.now());
            newReaction.setProfileId(profileId);
            newReaction.setReactionType(newType);
            setTargetId.accept(newReaction, targetId); // 👈 gọi đúng hàm để set postId/commentId

            return reactionMapper.toReactionResponse(saveReaction.apply(newReaction));
        }

        if (existingReaction.getReactionType() == newType) {
            deleteReaction.accept(existingReaction);
            return ReactionResponse.builder()
                    .postId(targetId)
                    .profileId(profileId)
                    .reactionType(null)
                    .action("REMOVED")
                    .build();
        }

        existingReaction.setReactionType(newType);
        return reactionMapper.toReactionResponse(saveReaction.apply(existingReaction));
    }


    public ReactionResponse reactToPost(ReactionCreationRequest request, Authentication authentication) {
        String profileId = getProfileIdFromAuthentication(authentication);
        String postId = request.getPostId();
        ReactionType newType = request.getReactionType();

        return handleReaction(
                postId,
                profileId,
                newType,
                postRepository::existsById,
                reactionRepository::findByPostIdAndProfileId,
                reactionRepository::save,
                reactionRepository::delete,
                (reaction, id) -> reaction.setPostId(id) // 👈 truyền cách set postId
        );
    }


    public ReactionResponse reactToComment(ReactionCreationRequest request, Authentication authentication) {
        String profileId = getProfileIdFromAuthentication(authentication);
        String commentId = request.getCommentId();
        ReactionType newType = request.getReactionType();

        return handleReaction(
                commentId,
                profileId,
                newType,
                commentRepository::existsById,
                reactionRepository::findByCommentIdAndProfileId,
                reactionRepository::save,
                reactionRepository::delete,
                (reaction, id) -> reaction.setCommentId(id) // 👈 truyền cách set commentId
        );
    }





    private String getProfileIdFromAuthentication(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String USER_ID = "userId";
        String userId = jwt.getClaimAsString(USER_ID);

        return userProfileClient.getActiveProfile(userId).getResult();
    }

    private PageResponse<ReactionResponse> buildPagedReactionResponse(
            Page<Reaction> pageData, int page
    ) {
        return PageResponse.<ReactionResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream()
                        .map(reactionMapper::toReactionResponse)
                        .toList())
                .build();
    }

    public PageResponse<ReactionResponse> getReactionsByPost(String postId, int size, int page) {
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = reactionRepository.findAllByPostId(postId, pageable);

        return buildPagedReactionResponse(pageData, page);
    }

    public PageResponse<ReactionResponse> getReactionsByComment(String commentId, int size, int page) {
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = reactionRepository.findAllByCommentId(commentId, pageable);

        return buildPagedReactionResponse(pageData, page);
    }


    private long getReactionCount(String targetId, Function<String, Long> countById) {
        return countById.apply(targetId);
    }

    public long getCountReactionsByPost(String postId) {
        return getReactionCount(postId, reactionRepository::countByPostId);
    }

    public long getCountReactionsByComment(String commentId) {
        return getReactionCount(commentId, reactionRepository::countByCommentId);
    }

    private Map<ReactionType, Long> getReactionSummaryByTarget(String targetId, Function<String, List<Reaction>> findReactionsByTarget) {
        List<Reaction> reactions = findReactionsByTarget.apply(targetId);
        return reactions.stream()
                .collect(Collectors.groupingBy(Reaction::getReactionType, Collectors.counting()));
    }



    public Map<ReactionType, Long> getReactionSummaryByPost(String postId) {
        return getReactionSummaryByTarget(postId, reactionRepository::findAllByPostId);
    }

    public Map<ReactionType, Long> getReactionSummaryByComment(String commentId) {
        return getReactionSummaryByTarget(commentId, reactionRepository::findAllByCommentId);
    }


    private ReactionType getUserReactionByTarget(String targetId, String profileId, BiFunction<String, String, Reaction> findReaction) {
        Reaction reaction = findReaction.apply(targetId, profileId);
        return reaction != null ? reaction.getReactionType() : null;
    }

    public ReactionType getUserReactionForPost(String postId, String profileId) {
        return getUserReactionByTarget(postId, profileId, reactionRepository::findByPostIdAndProfileId);
    }

    public ReactionType getUserReactionForComment(String commentId, String profileId) {
        return getUserReactionByTarget(commentId, profileId, reactionRepository::findByCommentIdAndProfileId);
    }



    //---------------ADMIN---------------
    private void removeAllReactionsByTarget(String targetId, Consumer<String> deleteReactions) {
        deleteReactions.accept(targetId);
    }


    public void removeAllReactionsByPost(String postId) {
        removeAllReactionsByTarget(postId, reactionRepository::deleteAllByPostId);
    }


    public void removeAllReactionsByComment(String commentId) {
        removeAllReactionsByTarget(commentId, reactionRepository::deleteAllByCommentId);
    }



    public void removeAllReactionsByProfile(String profileId) {
        reactionRepository.deleteAllByProfileId(profileId);
    }

    //-----------------ANALYTICS---------------
//    public List<String> getTopPostsByReaction(ReactionType type) {
//        return reactionRepository.findTopPostIdsByReactionType(type, PageRequest.of(0, 10));
//    }




}
