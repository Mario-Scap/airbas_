package com.afm.authservice.userdetails;

import model.auth.ERole;
import model.auth.UserBas;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import java.util.*;

public class appUser implements UserDetails {

    private final UserBas userBas;

    @Enumerated(EnumType.STRING) //questo vale per ERole
    private ERole role;


    public appUser(UserBas userBas) {
        this.userBas = userBas;

    }

    public appUser(UserBas userBas, ERole role) {
        this.userBas = userBas;
        this.role = role;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        SimpleGrantedAuthority auth = new SimpleGrantedAuthority(role.name());
        return Collections.singletonList(auth);
    }

    @Override
    public String getPassword() {
        return userBas.getPassword();
    }

    @Override
    public String getUsername() {
        return userBas.getEmail();
    }

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
        return userBas.getEnabled();
    }
}

