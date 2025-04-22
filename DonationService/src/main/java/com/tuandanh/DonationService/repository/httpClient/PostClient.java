package com.tuandanh.DonationService.repository.httpClient;

import com.tuandanh.DonationService.configuration.AuthenticationRequestInterceptor;
import com.tuandanh.DonationService.configuration.FeignConfig;
import com.tuandanh.DonationService.dto.ApiResponse;
import com.tuandanh.DonationService.dto.response.PostResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "post-service", url = "${app.service.post}",
        configuration = {FeignConfig.class, AuthenticationRequestInterceptor.class})
public interface PostClient {
    @GetMapping("/internal/postUsers/getPostByPostId/{postId}")
    ApiResponse<PostResponse> getPostByPostId(@PathVariable String postId);
}
