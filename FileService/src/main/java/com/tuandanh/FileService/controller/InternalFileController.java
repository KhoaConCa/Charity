package com.tuandanh.FileService.controller;

import com.tuandanh.FileService.dto.ApiResponse;
import com.tuandanh.FileService.dto.request.FileTypeRequest;
import com.tuandanh.FileService.dto.response.FileResponse;
import com.tuandanh.FileService.enums.FileType;
import com.tuandanh.FileService.service.aws3.FileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.apache.kafka.shaded.com.google.protobuf.Api;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/internal/aws3")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Internal File Controller", description = "API nội bộ để quản lý file, không cho phép client sử dụng.")
public class InternalFileController {
    FileService fileService;

    @Operation(
            summary = "Tải lên một file",
            description = "API nội bộ để tải lên một file, chỉ có thể sử dụng bởi các dịch vụ nội bộ, không cho phép client truy cập."
    )
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<String> uploadFile(
            @RequestPart("file") MultipartFile file,
            @RequestParam String profileId,
            @RequestParam FileType fileType) throws IOException {

        String url = fileService.uploadFile(file, profileId, fileType);

        return ApiResponse.<String>builder()
                .result(url)
                .build();
    }

    @Operation(
            summary = "Tải lên nhiều file",
            description = "API nội bộ để tải lên nhiều file cùng lúc, chỉ có thể sử dụng bởi các dịch vụ nội bộ, không cho phép client truy cập."
    )
    @PostMapping(value = "/uploadFiles", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<List<String>> uploadFiles(
            @RequestParam("files") List<MultipartFile> files,   // Danh sách các file cần upload
            @RequestParam("profileId") String profileId,         // ID người dùng
            @RequestParam("fileType") FileType fileType) throws IOException {
        List<String> urls = fileService.uploadFiles(files, profileId, fileType);

        return ApiResponse.<List<String>>builder()
                .result(urls)
                .build();
    }

    @Operation(
            summary = "Xóa 1 file",
            description = "API nội bộ để xóa file, chỉ có thể sử dụng bởi các dịch vụ nội bộ, không cho phép client truy cập."
    )
    @DeleteMapping("/deleteFile")
    public ApiResponse<String> deleteFile(@RequestParam String urlFile){
        fileService.deleteFile(urlFile);

        return ApiResponse.<String>builder()
                .result("delete File Success")
                .build();
    }

    @Operation(
            summary = "Xóa nhiều file",
            description = "API nội bộ để xóa file, chỉ có thể sử dụng bởi các dịch vụ nội bộ, không cho phép client truy cập."
    )
    @PostMapping(value = "/deleteFiles", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ApiResponse<String> deleteFiles(@RequestBody List<String> urlFiles){
        fileService.deleteFiles(urlFiles);

        return ApiResponse.<String>builder()
                .result("delete File Success")
                .build();
    }

    @GetMapping("/getFilesByProfileId/{profileId}")
    public ApiResponse<List<FileResponse>> getFilesByProfileId(@PathVariable String profileId){
        List<FileResponse> fileResponses = fileService.getUserFiles(profileId);

        return ApiResponse.<List<FileResponse>>builder()
                .result(fileResponses)
                .build();
    }

    @GetMapping("/getUserDetailsTypeFiles/{profileId}")
    public ApiResponse<List<FileResponse>> getUserDetailsTypeFiles(@PathVariable String profileId,
                                                                   @RequestBody FileTypeRequest fileTypeRequest){
        List<FileResponse> fileResponses = fileService.getUserDetailsTypeFiles(profileId, fileTypeRequest);

        return ApiResponse.<List<FileResponse>>builder()
                .result(fileResponses)
                .build();
    }

    @GetMapping("/getFilesByPostId/{postId}")
    public ApiResponse<List<FileResponse>> getFilesByPostId(@PathVariable String postId){
        List<FileResponse> fileResponses = fileService.getUserFiles(postId);

        return ApiResponse.<List<FileResponse>>builder()
                .result(fileResponses)
                .build();
    }
}

