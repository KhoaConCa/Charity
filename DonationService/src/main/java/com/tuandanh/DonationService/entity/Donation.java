package com.tuandanh.DonationService.entity;

import com.tuandanh.DonationService.enums.DonationStatus;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

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
    String donorId;
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
    Long paymentRefId;

    @Column(name = "created_at", nullable = false)
    LocalDateTime createdAt;

    @Column(name = "paid_at")
    LocalDateTime paidAt;

    @OneToMany(mappedBy = "donation", cascade = CascadeType.ALL, orphanRemoval = true)
    List<PaymentLog> paymentLogs; // Danh sách các payment log liên kết với donation

}
