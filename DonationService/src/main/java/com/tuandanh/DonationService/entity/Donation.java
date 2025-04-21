package com.tuandanh.DonationService.entity;

import com.tuandanh.DonationService.enums.DonationStatus;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "donations")
public class Donation {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;
    @Column(name = "post_id", nullable = false)
    String postId;
    @Column(name = "donor_id", nullable = false)
    Long donorId;
    @Column(nullable = false, precision = 12, scale = 2)
    BigDecimal amount;

    @Column(columnDefinition = "TEXT")
    String message;

    @Column(nullable = false)
    boolean isAnonymous;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    DonationStatus status;

    @Column(nullable = false, length = 50)
    String paymentMethod;

    @Column(name = "payment_ref_id", length = 100)
    String paymentRefId;

    @Column(name = "created_at", nullable = false)
    LocalDateTime createdAt;

    @Column(name = "paid_at")
    LocalDateTime paidAt;

}
