package com.tuandanh.DonationService.controller;

import com.tuandanh.DonationService.dto.ApiResponse;
import com.tuandanh.DonationService.dto.PageResponse;
import com.tuandanh.DonationService.dto.PostDonationTotal;
import com.tuandanh.DonationService.dto.request.DonationCreationRequest;
import com.tuandanh.DonationService.dto.response.DonationResponse;
import com.tuandanh.DonationService.service.DonationService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/userDonation")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class DonationController {
    DonationService service;

    @GetMapping("/total/{postId}")
    public ApiResponse<BigDecimal> getTotalByPostId(@PathVariable String postId) {
        var total = service.getTotalByPostId(postId);

        return ApiResponse.<BigDecimal>builder()
                .result(total)
                .build();
    }

    @GetMapping("/total")
    public ApiResponse<List<PostDonationTotal>> getTotalForAllPosts() {
        var list =  service.getAllPostDonationTotals();

        return ApiResponse.<List<PostDonationTotal>>builder()
                .result(list)
                .build();
    }

    @PostMapping
    public ApiResponse<DonationResponse> createDonation(@RequestBody @Valid DonationCreationRequest donationCreationRequest){
        DonationResponse donationResponse = service.createDonation(donationCreationRequest);

        return ApiResponse.<DonationResponse>builder()
                .result(donationResponse)
                .build();
    }

    @GetMapping("/{donationId}")
    public ApiResponse<DonationResponse> getDonation(@PathVariable String donationId){
        DonationResponse donationResponse = service.getDonationById(donationId);

        return ApiResponse.<DonationResponse>builder()
                .result(donationResponse)
                .build();
    }

    @GetMapping("/ofDonor/{donorId}")
    public ApiResponse<PageResponse<DonationResponse>> getDonationByDonorId(
            @PathVariable String donorId,
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size){

        PageResponse<DonationResponse> response = service.getAllDonationOfUser(donorId, page, size);

        return ApiResponse.<PageResponse<DonationResponse>>builder()
                .result(response)
                .build();
    }

    @GetMapping("/ofPost/{postId}")
    public ApiResponse<PageResponse<DonationResponse>> getDonationByPostId(
            @PathVariable String postId,
            @RequestParam(value = "page", required = false, defaultValue = "1") int page,
            @RequestParam(value = "size", required = false, defaultValue = "10") int size
    ){
        PageResponse<DonationResponse> response = service.getAllDonationOfUser(postId, page, size);

        return ApiResponse.<PageResponse<DonationResponse>>builder()
                .result(response)
                .build();
    }
}
