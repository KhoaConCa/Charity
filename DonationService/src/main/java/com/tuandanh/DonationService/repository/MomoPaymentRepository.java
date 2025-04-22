package com.tuandanh.DonationService.repository;

import com.tuandanh.DonationService.entity.MoMoPayment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MomoPaymentRepository extends JpaRepository<MoMoPayment, String> {
    Optional<MoMoPayment> findByOrderId(String orderId);
}
