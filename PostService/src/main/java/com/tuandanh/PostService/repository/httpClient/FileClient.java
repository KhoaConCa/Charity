package com.tuandanh.PostService.repository.httpClient;


import com.tuandanh.PostService.configuration.AuthenticationRequestInterceptor;
import com.tuandanh.PostService.configuration.FeignConfig;
import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.response.FileResponse;
import com.tuandanh.PostService.enums.FileType;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@FeignClient(name = "file-service", url = "${app.service.file}",
        configuration = {FeignConfig.class, AuthenticationRequestInterceptor.class})
public interface FileClient {
    @PostMapping(value = "/internal/aws3/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    ApiResponse<String> uploadFile(
            @RequestPart("file") MultipartFile file,
            @RequestParam String profileId,
            @RequestParam FileType fileType);

    @PostMapping(value = "/internal/aws3/uploadFiles", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    ApiResponse<List<String>> uploadFiles(
            @RequestPart("files") List<MultipartFile> file,
            @RequestParam String profileId,
            @RequestParam FileType fileType);

    @DeleteMapping("/internal/aws3/deleteFile")
    ApiResponse<String> deleteFile(@RequestParam String urlFile);

    @PostMapping(value = "/internal/aws3/deleteFiles", consumes = MediaType.APPLICATION_JSON_VALUE)
    ApiResponse<String> deleteFiles(@RequestBody List<String> urlFile);

    @GetMapping("/internal/aws3/getFilesByPostId/{postId}")
    public ApiResponse<List<FileResponse>> getFilesByPostId(@PathVariable String postId);

}
