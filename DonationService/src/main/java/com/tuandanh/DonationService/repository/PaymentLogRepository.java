package com.tuandanh.DonationService.repository;

import com.tuandanh.DonationService.entity.PaymentLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentLogRepository extends JpaRepository<PaymentLog, String> {
}
