package com.tuandanh.notificationService.controller;

import com.tuandanh.notificationService.dto.ApiResponse;
import com.tuandanh.notificationService.dto.request.EmailRequest;
import com.tuandanh.notificationService.dto.response.EmailResponse;
import com.tuandanh.notificationService.service.EmailService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/email")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class EmailController {
    EmailService emailService;

    @PostMapping("/send")
    public ApiResponse<EmailResponse> sendEmail(@RequestBody EmailRequest request) {
        return ApiResponse.<EmailResponse>builder()
                .result(emailService.sendEmail(request))
                .build();
    }
    @PostMapping("/print")
    public ApiResponse<String> print(){
        return ApiResponse.<String>builder()
                .result(emailService.print())
                .build();
    }
}
