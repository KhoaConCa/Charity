package com.tuandanh.PostService.controller;

import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.PageResponse;
import com.tuandanh.PostService.dto.request.PostCreationRequest;
import com.tuandanh.PostService.dto.request.PostUpdateRequest;
import com.tuandanh.PostService.dto.response.PostResponse;
import com.tuandanh.PostService.service.PostService;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/postUsers")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PostController {
    PostService postService;

    @GetMapping("/myPosts")
    public ApiResponse<PageResponse<PostResponse>> getMyPosts(
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size,
            @Parameter(hidden = true) Authentication authentication
    ) {
        PageResponse<PostResponse> postResponses = postService.getMyPosts(page, size, authentication);

        return ApiResponse.<PageResponse<PostResponse>>builder()
                .result(postResponses)
                .build();
    }

    // API tạo bài viết với file (multipart/form-data)
    @PostMapping(value = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<PostResponse> createPost(
            @RequestPart("postCreationRequest") PostCreationRequest postCreationRequest,
            @RequestPart(value = "files", required = false) List<MultipartFile> mediaFiles,
            @RequestHeader("Authorization") String authorization) {
        PostResponse postResponse = postService.createPost(postCreationRequest, mediaFiles, authorization);

        return ApiResponse.<PostResponse>builder()
                .result(postResponse)
                .build();
    }

    @PutMapping(value = "/{postId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<PostResponse> updatePost(
            @PathVariable String postId,
            @RequestPart("postUpdateRequest") @Valid PostUpdateRequest postUpdateRequest,
            @RequestPart(value = "files", required = false) List<MultipartFile> newMediaFiles,
            @RequestParam(value = "filesToRemove", required = false) List<String> filesToRemove,
            @RequestHeader("Authorization") String authorization
    ) {
        PostResponse postResponse = postService.updatePost(postId, postUpdateRequest,
                newMediaFiles, filesToRemove, authorization);

        return ApiResponse.<PostResponse>builder()
                .result(postResponse)
                .build();
    }

    @DeleteMapping(value = "/{postId}")
    public ApiResponse<String> deletePost(@PathVariable String postId, Authentication authentication) {
        postService.deletePost(postId, authentication);

        return ApiResponse.<String>builder()
                .result("delete Post successfully")
                .build();
    }

    @GetMapping("/getAllPosts")
    public ApiResponse<PageResponse<PostResponse>> getAllPosts(
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size

    ){
        PageResponse<PostResponse> posts = postService.getAllPosts(page, size);

        return ApiResponse.<PageResponse<PostResponse>>builder()
                .result(posts)
                .build();
    }

    @GetMapping("/getPostByPostId/{postId}")
    public ApiResponse<PostResponse> getPostByPostId(@PathVariable String postId){
        PostResponse postResponse = postService.getPostByPostId(postId);

        return ApiResponse.<PostResponse>builder()
                .result(postResponse)
                .build();
    }

    @GetMapping("/getPostsByProfileId/{profileId}")
    public ApiResponse<PageResponse<PostResponse>> getPostsByProfileId(@PathVariable String profileId,
        @RequestParam(value = "page", required = false, defaultValue = "1") int page,
         @RequestParam(value = "size", required = false, defaultValue = "10") int size
    ){
        PageResponse<PostResponse> postResponses = postService.getAllPostsByProfileId(profileId, page, size);

        return ApiResponse.<PageResponse<PostResponse>>builder()
                .result(postResponses)
                .build();
    }
}
