package com.tuandanh.DonationService.dto;

import java.math.BigDecimal;

public interface PostDonationTotal {
    String getPostId();
    BigDecimal getTotalAmount();
}