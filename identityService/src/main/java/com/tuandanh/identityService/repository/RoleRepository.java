package com.tuandanh.identityService.repository;

import com.tuandanh.identityService.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {
    @Query("""
    SELECT r.name, r.description, p.name
    FROM Role r
    JOIN r.permissions p
""")
    List<Object[]> findRoleWithPermissionsFlat();

}
