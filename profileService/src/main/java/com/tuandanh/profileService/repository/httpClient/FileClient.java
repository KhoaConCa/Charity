package com.tuandanh.profileService.repository.httpClient;

import com.tuandanh.profileService.configuration.AuthenticationRequestInterceptor;
import com.tuandanh.profileService.configuration.FeignConfig;
import com.tuandanh.profileService.dto.ApiResponse;
import com.tuandanh.profileService.dto.request.UploadFileRequest;
import com.tuandanh.profileService.dto.response.UploadFileResponse;
import com.tuandanh.profileService.enums.FileType;
import org.hibernate.mapping.Map;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;



@FeignClient(name = "file-service", url = "${app.service.file}",
        configuration = {FeignConfig.class, AuthenticationRequestInterceptor.class})
public interface FileClient {
    @PostMapping(value = "/internal/aws3/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    ApiResponse<String> uploadFile(
            @RequestPart("file") MultipartFile file,
            @RequestParam String profileId,
            @RequestParam FileType fileType);

    @DeleteMapping("/internal/aws3")
    ApiResponse<String> deleteFile(@RequestParam String urlFile);
}
