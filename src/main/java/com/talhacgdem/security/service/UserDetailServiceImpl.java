package com.talhacgdem.security.service;

import com.talhacgdem.security.entity.User;
import com.talhacgdem.security.repository.UserRepository;
import com.talhacgdem.security.security.JwtUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return JwtUserDetails.create(userRepository.findByUsername(username));
    }

    public UserDetails loadUserById(Long Id){
        return JwtUserDetails.create(userRepository.findById(Id).get());
    }
}
