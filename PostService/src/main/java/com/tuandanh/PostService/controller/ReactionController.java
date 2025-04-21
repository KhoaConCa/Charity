package com.tuandanh.PostService.controller;

import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.PageResponse;
import com.tuandanh.PostService.dto.request.ReactionCreationRequest;
import com.tuandanh.PostService.dto.response.ReactionResponse;
import com.tuandanh.PostService.enums.ReactionType;
import com.tuandanh.PostService.service.ReactionService;
import io.swagger.v3.oas.annotations.Parameter;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/reactions")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ReactionController {
    ReactionService reactionService;

    @PostMapping("/reactToPost")
    public ApiResponse<ReactionResponse> reactToPost(
            @RequestBody ReactionCreationRequest reactionCreationRequest,
            @Parameter(hidden = true) Authentication authentication) {
        ReactionResponse reactionResponse = reactionService.reactToPost(reactionCreationRequest, authentication);

        return ApiResponse.<ReactionResponse>builder()
                .result(reactionResponse)
                .build();
    }

    @PostMapping("/reactToComment")
    public ApiResponse<ReactionResponse> reactToComment(
            @RequestBody ReactionCreationRequest reactionCreationRequest,
            @Parameter(hidden = true) Authentication authentication) {
        ReactionResponse reactionResponse = reactionService.reactToComment(reactionCreationRequest, authentication);

        return ApiResponse.<ReactionResponse>builder()
                .result(reactionResponse)
                .build();
    }

    @GetMapping("/inPost/{postId}")
    public ApiResponse<PageResponse<ReactionResponse>> getReactionsByPost(
            @PathVariable String postId,
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size) {
        PageResponse<ReactionResponse> reactionResponses = reactionService.getReactionsByPost(postId, size, page);

        return ApiResponse.<PageResponse<ReactionResponse>>builder()
                .result(reactionResponses)
                .build();
    }

    @GetMapping("/inComment/{commentId}")
    public ApiResponse<PageResponse<ReactionResponse>> getReactionsByComment(
            @PathVariable String commentId,
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size) {
        PageResponse<ReactionResponse> reactionResponses = reactionService.getReactionsByComment(commentId, size, page);

        return ApiResponse.<PageResponse<ReactionResponse>>builder()
                .result(reactionResponses)
                .build();
    }

    @GetMapping("/counts/{postId}")
    public ApiResponse<Long> countReactionsByPost(@PathVariable String postId) {
        Long number = reactionService.getCountReactionsByPost(postId);

        return ApiResponse.<Long>builder()
                .result(number)
                .build();
    }

    @GetMapping("/counts/{commentId}")
    public ApiResponse<Long> countReactionsByComment(@PathVariable String commentId) {
        Long number = reactionService.getCountReactionsByComment(commentId);

        return ApiResponse.<Long>builder()
                .result(number)
                .build();
    }

    @GetMapping("/summary/inPost/{postId}")
    public ApiResponse<Map<ReactionType, Long>> getSummaryOfReactionInPost(@PathVariable String postId) {
        Map<ReactionType, Long> summary = reactionService.getReactionSummaryByPost(postId);

        return ApiResponse.<Map<ReactionType, Long>>builder()
                .result(summary)
                .build();
    }

    @GetMapping("/summary/inComment/{commentId}")
    public ApiResponse<Map<ReactionType, Long>> getSummaryOfReactionInComment(@PathVariable String commentId) {
        Map<ReactionType, Long> summary = reactionService.getReactionSummaryByComment(commentId);

        return ApiResponse.<Map<ReactionType, Long>>builder()
                .result(summary)
                .build();
    }

    @GetMapping("/user/inPost/{postId}/{profileId}")
    public ApiResponse<ReactionType> getUserReaction(@PathVariable String postId, @PathVariable String profileId) {
        ReactionType reactionResponse = reactionService.getUserReactionForPost(postId, profileId);

        return ApiResponse.<ReactionType>builder()
                .result(reactionResponse)
                .build();
    }

    @GetMapping("/user/inComment/{commentId}/{profileId}")
    public ApiResponse<ReactionType> getUserReactionForComment(
            @PathVariable String commentId, @PathVariable String profileId) {
        ReactionType reactionResponse = reactionService.getUserReactionForComment(commentId, profileId);

        return ApiResponse.<ReactionType>builder()
                .result(reactionResponse)
                .build();
    }

    @DeleteMapping("/{postId}")
    public ApiResponse<String> removeReactionInPost(@PathVariable String postId) {
        reactionService.removeAllReactionsByPost(postId);

        return ApiResponse.<String>builder()
                .result("remove reaction in post successfully")
                .build();
    }

    @DeleteMapping("/{commentId}")
    public ApiResponse<String> removeReactionInComment(@PathVariable String commentId) {
        reactionService.removeAllReactionsByComment(commentId);

        return ApiResponse.<String>builder()
                .result("remove reaction in comment successfully")
                .build();
    }

    @DeleteMapping("/{profileId}")
    public ApiResponse<String> removeProfileReaction(@PathVariable String profileId) {
        reactionService.removeAllReactionsByProfile(profileId);

        return ApiResponse.<String>builder()
                .result("remove reaction of this profile successfully")
                .build();
    }
}
