package com.afm.authservice.service;



import com.afm.authservice.repository.UserBasRepository;
import com.afm.authservice.userdetails.appUser;
import lombok.RequiredArgsConstructor;
import model.auth.UserBas;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SpringUserService implements UserDetailsService {
    private final UserBasRepository userBasRepository;

    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserBas userBas = userBasRepository.findByEmail(email);

        if (userBas == null) {
            throw new UsernameNotFoundException("email non trovata " + email);
        }
/*
        UserDetails user = User.builder()
                .username(userBas.getEmail())
                .password(userBas.getPassword())
                .roles(ERole.USER.name())
                .build();
 */
        return new appUser(userBas);
    }
}