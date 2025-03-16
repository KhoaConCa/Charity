package com.tuandanh.identityService.repository;

import com.tuandanh.identityService.entity.Device;
import com.tuandanh.identityService.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DeviceRepository extends JpaRepository<Device, String> {
    boolean existsByUserAndDeviceInfo(User user, String deviceInfo);
    Device findByUserAndDeviceInfo(User user, String deviceInfo);
}
