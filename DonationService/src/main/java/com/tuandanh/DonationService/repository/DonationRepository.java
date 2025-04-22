package com.tuandanh.DonationService.repository;

import com.tuandanh.DonationService.dto.PostDonationTotal;
import com.tuandanh.DonationService.entity.Donation;
import feign.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.math.BigDecimal;
import java.util.List;

public interface DonationRepository extends JpaRepository<Donation, String> {
    Page<Donation> findAllByDonorId(String donorId, Pageable pageable);
    Page<Donation> findAllByPostId(String postId, Pageable pageable);
    @Query("""
        SELECT d.postId AS postId, SUM(d.amount) AS totalAmount
        FROM Donation d
        WHERE d.status = 'SUCCESS'
        GROUP BY d.postId
    """)
    List<PostDonationTotal> getTotalDonationByPost();

    @Query("""
        SELECT SUM(d.amount)
        FROM Donation d
        WHERE d.status = 'SUCCESS' AND d.postId = :postId
    """)
    BigDecimal getTotalByPostId(@Param("postId") String postId);

}
