package com.tuandanh.identityService.service;

import com.tuandanh.identityService.dto.RoleDTO;
import com.tuandanh.identityService.dto.request.RoleRequest;
import com.tuandanh.identityService.dto.response.RoleResponse;
import com.tuandanh.identityService.mapper.RoleMapper;
import com.tuandanh.identityService.repository.PermissionRepository;
import com.tuandanh.identityService.repository.RoleRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RoleService {
    RoleRepository roleRepository;
    PermissionRepository permissionRepository;
    RoleMapper roleMapper;

    public RoleResponse create(RoleRequest request) {
        var role = roleMapper.toRole(request);

        var permissions = permissionRepository.findAllById(request.getPermissions());
        role.setPermissions(new HashSet<>(permissions));

        role = roleRepository.save(role);
        return roleMapper.toRoleResponse(role);
    }

    public List<RoleResponse> getAll() {
        return roleRepository.findAll().stream().map(roleMapper::toRoleResponse).toList();
    }

    public List<RoleDTO> getAllVersion1() {
        List<Object[]> flat = roleRepository.findRoleWithPermissionsFlat();

        Map<String, RoleDTO> map = new LinkedHashMap<>();

        for (Object[] row : flat) {
            String name = (String) row[0];
            String description = (String) row[1];
            String permission = (String) row[2];

            map.computeIfAbsent(name, n ->
                    new RoleDTO(name, description, new ArrayList<>())
            ).permissions().add(permission);
        }

        return new ArrayList<>(map.values());
    }


    public void delete(String role) {
        roleRepository.deleteById(role);
    }
}
