package com.tuandanh.DonationService.entity;

import com.tuandanh.DonationService.enums.PaymentLogStatus;
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
@Table(name = "payment_logs")
public class PaymentLog {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "donation_id", referencedColumnName = "id", insertable = false, updatable = false)
    Donation donation; // Thiết lập mối quan hệ với Donation

    @Column(name = "donation_id", nullable = false)
    String donationId;  // Vẫn giữ lại column này để lưu giá trị donationId

    @Column(name = "gateway_name", length = 50)
    String gatewayName;

    @Column(columnDefinition = "TEXT")
    String payload;

    PaymentLogStatus status;

    LocalDateTime createdAt;

}
