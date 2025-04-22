package com.tuandanh.PostService.controller;

import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.response.PostResponse;
import com.tuandanh.PostService.service.PostService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/postUsers")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class InternalPostController {
    PostService postService;

    @GetMapping("/getPostByPostId/{postId}")
    public ApiResponse<PostResponse> getPostByPostId(@PathVariable String postId){
        PostResponse postResponse = postService.getPostByPostId(postId);

        return ApiResponse.<PostResponse>builder()
                .result(postResponse)
                .build();
    }
}
