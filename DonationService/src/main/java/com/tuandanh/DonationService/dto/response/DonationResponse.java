package com.tuandanh.DonationService.dto.response;

import com.tuandanh.DonationService.enums.DonationStatus;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class DonationResponse {
    String id;
    String postId;
    String donorId;
    BigDecimal amount;
    String message;
    boolean isAnonymous;
    DonationStatus status;
    String paymentMethod;
    String paymentRefId;
    LocalDateTime createdAt;
    LocalDateTime paidAt;
    String payUrl;
}
