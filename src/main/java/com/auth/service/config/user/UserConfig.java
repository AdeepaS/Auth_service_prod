package com.auth.service.config.user;

import java.util.UUID;
import com.auth.service.entity.UserEntity;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@RequiredArgsConstructor                               //can inject the constructor injection
public class UserConfig implements UserDetails {

    private final UserEntity userEntity;
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return Arrays
//                .stream(userEntity
//                        .getRoles()
//                        .split(","))
//                .map(SimpleGrantedAuthority::new)
//                .toList();
//    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String roleStr = userEntity.getRole() != null ? userEntity.getRole().name() : "TECHNICIAN";
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + roleStr));
    }

    @Override
    public String getPassword() {
        return userEntity.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return userEntity.getEmail();
    }

    public String getMobileNumber(){return  userEntity.getMobileNumber();}

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
