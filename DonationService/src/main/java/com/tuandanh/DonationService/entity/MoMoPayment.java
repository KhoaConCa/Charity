package com.tuandanh.DonationService.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Entity
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "momo_payments")
public class MoMoPayment {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;
    String orderId;
    String donationId;
    String requestId;
    LocalDateTime createdAt;
}
