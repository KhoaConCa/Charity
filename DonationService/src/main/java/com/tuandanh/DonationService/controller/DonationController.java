package com.tuandanh.DonationService.controller;

import com.tuandanh.DonationService.dto.ApiResponse;
import com.tuandanh.DonationService.dto.PageResponse;
import com.tuandanh.DonationService.dto.request.DonationCreationRequest;
import com.tuandanh.DonationService.dto.response.DonationResponse;
import com.tuandanh.DonationService.service.DonationService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/userDonation")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class DonationController {
    DonationService service;

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
