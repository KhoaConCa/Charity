package com.tuandanh.identityService.service.oauth;

import com.tuandanh.identityService.constant.PredefinedRole;
import com.tuandanh.identityService.entity.Role;
import com.tuandanh.identityService.entity.User;
import com.tuandanh.identityService.repository.RoleRepository;
import com.tuandanh.identityService.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class OAuth2ServiceImpl implements OAuth2Service {

    UserRepository userRepository;
    RoleRepository roleRepository;

    @Override
    public User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");

        return userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            HashSet<Role> roles = new HashSet<>();
            roleRepository.findById(PredefinedRole.USER_ROLE).ifPresent(roles::add);

            newUser.setRoles(roles);
            newUser.setUsername(email);
            newUser.setEmail(email);
            newUser.setFirstName(firstName);  // Cần có trường firstName trong entity
            newUser.setLastName(lastName);    // Cần có trường lastName trong entity
            newUser.setProvider(userRequest.getClientRegistration().getRegistrationId().toUpperCase());
            return userRepository.save(newUser);
        });
    }
}
