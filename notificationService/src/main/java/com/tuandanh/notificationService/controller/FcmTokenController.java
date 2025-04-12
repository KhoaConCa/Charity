package com.tuandanh.notificationService.controller;

import com.tuandanh.notificationService.dto.ApiResponse;
import com.tuandanh.notificationService.dto.request.FcmTokenRequest;
import com.tuandanh.notificationService.entity.FcmToken;
import com.tuandanh.notificationService.service.FcmService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/fcm-token")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FcmTokenController {
    FcmService fcmService;

    @PostMapping("/save")
    public ApiResponse<String> saveToken(@RequestBody FcmTokenRequest fcmTokenRequest) {
        fcmService.saveOrUpdateToken(fcmTokenRequest);

        return ApiResponse.<String>builder()
                .result("save token successful")
                .build();
    }

    @GetMapping("/{userId}")
    public ApiResponse<List<FcmToken>> getFcmToken(@PathVariable String userId) {
        List<FcmToken> fcmTokenList = fcmService.getTokensByUserId(userId);

        return ApiResponse.<List<FcmToken>>builder()
                .result(fcmTokenList)
                .build();
    }

    @DeleteMapping("/delete/{fcmToken}")
    public ApiResponse<String> deleteFcmToken(@PathVariable String fcmToken) {
        fcmService.deleteToken(fcmToken);

        return ApiResponse.<String>builder()
                .result("delete token successful")
                .build();
    }


}
