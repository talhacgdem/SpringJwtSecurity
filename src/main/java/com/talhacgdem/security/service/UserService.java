package com.talhacgdem.security.service;

import com.talhacgdem.security.entity.User;
import com.talhacgdem.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getOneUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
