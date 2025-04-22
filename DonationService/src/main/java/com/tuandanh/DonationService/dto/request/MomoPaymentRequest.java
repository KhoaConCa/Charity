package com.tuandanh.DonationService.dto.request;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class MomoPaymentRequest {
    String partnerCode;
    String accessKey;
    String requestId;
    String amount;
    String orderId;
    String orderInfo;
    String returnUrl;
    String notifyUrl;
    String extraData;
    String requestType;
    String signature;
    String lang;
}
