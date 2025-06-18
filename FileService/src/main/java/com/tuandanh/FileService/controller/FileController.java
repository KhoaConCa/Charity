package com.tuandanh.FileService.controller;

import com.tuandanh.FileService.dto.ApiResponse;
import com.tuandanh.FileService.dto.request.BatchUploadUrlRequest;
import com.tuandanh.FileService.dto.response.PresignedUploadResponse;
import com.tuandanh.FileService.service.aws3.FileService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FileController {
    FileService fileService;

    @GetMapping("/presigned-url")
    public ApiResponse<String> generatePresignedUrl(
            @RequestParam String fileName,
            @RequestParam String contentType) {

        String presignedUrl = fileService.generatePresignedUploadUrl(fileName, contentType);
        return ApiResponse.<String>builder()
                .result(presignedUrl)
                .build();
    }

    @PostMapping("/generate-batch-upload-urls")
    public ApiResponse<List<PresignedUploadResponse>> generateBatchUploadUrls(
            @RequestBody BatchUploadUrlRequest request) {
        List<PresignedUploadResponse> responses = fileService.generateBatchUploadUrls(request);
        return ApiResponse.<List<PresignedUploadResponse>>builder()
                .result(responses)
                .build();
    }


}
