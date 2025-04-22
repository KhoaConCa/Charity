package com.tuandanh.DonationService.repository;

import com.tuandanh.DonationService.entity.Donation;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DonationRepository extends JpaRepository<Donation, String> {
    Page<Donation> findAllByDonorId(String donorId, Pageable pageable);
    Page<Donation> findAllByPostId(String postId, Pageable pageable);

}
