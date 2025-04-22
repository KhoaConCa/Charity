package com.tuandanh.DonationService.controller;

import com.tuandanh.DonationService.dto.ApiResponse;
import com.tuandanh.DonationService.repository.PaymentLogRepository;
import com.tuandanh.DonationService.service.momo.MomoPaymentService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/momo")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class MomoCallbackController {
    PaymentLogRepository paymentLogRepository;
    MomoPaymentService momoPaymentService;

    @PostMapping("/ipn")
    public ApiResponse<String> handleIPN(@RequestBody Map<String, Object> payload){
        String result = momoPaymentService.handleIPN(payload);

        return ApiResponse.<String>builder()
                .result(result)
                .build();
    }
}
