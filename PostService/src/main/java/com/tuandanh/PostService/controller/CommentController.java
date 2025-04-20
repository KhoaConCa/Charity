package com.tuandanh.PostService.controller;

import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.PageResponse;
import com.tuandanh.PostService.dto.request.CommentCreationRequest;
import com.tuandanh.PostService.dto.request.CommentUpdateRequest;
import com.tuandanh.PostService.dto.response.CommentResponse;
import com.tuandanh.PostService.service.CommentService;
import io.swagger.v3.oas.annotations.Parameter;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/comments")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CommentController {
    CommentService commentService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<CommentResponse> createComment(
            @RequestPart CommentCreationRequest commentCreationRequest,
            @RequestPart(value = "files", required = false) List<MultipartFile> mediaFiles,
            @Parameter(hidden = true) Authentication authentication){
        CommentResponse commentResponse = commentService.createComment(
                commentCreationRequest,
                mediaFiles,
                authentication
        );

        return ApiResponse.<CommentResponse>builder()
                .result(commentResponse)
                .build();
    }

    @PutMapping(value = "/{commentId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<CommentResponse> updateComment(
            @RequestPart CommentUpdateRequest commentUpdateRequest,
            @RequestPart(value = "files", required = false) List<MultipartFile> mediaFiles,
            @RequestParam(value = "filesToRemove", required = false) List<String> filesToRemove,
            @PathVariable String commentId
    ){
        CommentResponse commentResponse = commentService.updateComment(
                commentUpdateRequest,
                mediaFiles,
                commentId,
                filesToRemove
        );

        return ApiResponse.<CommentResponse>builder()
                .result(commentResponse)
                .build();
    }

    @DeleteMapping("/{commentId}")
    public ApiResponse<String> deleteComment(@PathVariable String commentId){
        commentService.deleteComment(commentId);

        return ApiResponse.<String>builder()
                .result("delete comment successfully")
                .build();
    }

    @DeleteMapping("/reply/{commentId}")
    public ApiResponse<String> deleteReply(@PathVariable String commentId){
        commentService.deleteReply(commentId);

        return ApiResponse.<String>builder()
                .result("delete reply successfully")
                .build();
    }

    @GetMapping("/inPost/{postId}")
    public ApiResponse<PageResponse<CommentResponse>> getInPostComments(
            @PathVariable String postId,
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size
    ){
        PageResponse<CommentResponse> commentResponsePageResponse = commentService.getCommentsByPost(postId, page, size);

        return ApiResponse.<PageResponse<CommentResponse>>builder()
                .result(commentResponsePageResponse)
                .build();
    }

    @GetMapping("/inComment/{commentId}")
    public ApiResponse<PageResponse<CommentResponse>> getReplies(
            @PathVariable String commentId,
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size
    ){
        PageResponse<CommentResponse> commentResponsePageResponse = commentService
                .getRepliesByComment(commentId, page, size);

        return ApiResponse.<PageResponse<CommentResponse>>builder()
                .result(commentResponsePageResponse)
                .build();
    }

    @GetMapping("/countReplies/{commentId}")
    public ApiResponse<Long> countReplies(@PathVariable String commentId){
        Long number = commentService.getCountRepliesInComment(commentId);

        return ApiResponse.<Long>builder()
                .result(number)
                .build();
    }

    @GetMapping("/countComments/{postId}")
    public ApiResponse<Long> countComments(@PathVariable String postId){
        Long number = commentService.getCountCommentsInPost(postId);

        return ApiResponse.<Long>builder()
                .result(number)
                .build();
    }

    @GetMapping("/oneComment/{commentId}")
    public ApiResponse<CommentResponse> getOneComment(@PathVariable String commentId){
        CommentResponse commentResponse = commentService.getCommentById(commentId);

        return ApiResponse.<CommentResponse>builder()
                .result(commentResponse)
                .build();
    }

    @GetMapping("/userComments/{profileId}")
    public ApiResponse<PageResponse<CommentResponse>> getUserComments(
            @PathVariable String profileId,
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size
    ){
        PageResponse<CommentResponse> commentResponsePageResponse = commentService.getUserComments(profileId, page, size);

        return ApiResponse.<PageResponse<CommentResponse>>builder()
                .result(commentResponsePageResponse)
                .build();
    }

    @DeleteMapping("/inPost/{postId}")
    public ApiResponse<String> deleteAllCommentsInPost(@PathVariable String postId){
        commentService.deleteAllCommentsByPost(postId);

        return ApiResponse.<String>builder()
                .result("delete all comment in post successfully")
                .build();
    }

    @DeleteMapping("/ofProfile/{profileId}")
    public ApiResponse<String> deleteAllCommentsInProfile(@PathVariable String profileId){
        commentService.deleteAllCommentByProfileId(profileId);

        return ApiResponse.<String>builder()
                .result("delete all comment in profile successfully")
                .build();
    }


}
