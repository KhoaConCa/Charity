package com.tuandanh.DonationService.dto.request;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class DonationCreationRequest {
    String postId;
    String donorId;
    BigDecimal amount;
    String message;
    boolean isAnonymous;
    String paymentMethod;
}
