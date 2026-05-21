package com.auth.service.mapper;

import java.util.UUID;

import com.auth.service.entity.UserEntity;
import java.util.UUID;
import com.auth.service.dto.UserRegistrationDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserInfoMapper {

    private final PasswordEncoder passwordEncoder;
    public UserEntity convertToEntity(UserRegistrationDto userRegistrationDto) {
        UserEntity userInfoEntity = new UserEntity();
        userInfoEntity.setName(userRegistrationDto.userName());
        userInfoEntity.setEmail(userRegistrationDto.userEmail());
        userInfoEntity.setMobileNumber(userRegistrationDto.userMobileNo());
        userInfoEntity.setRole(com.auth.service.entity.Role.TECHNICIAN);

        return userInfoEntity;
    }
}
