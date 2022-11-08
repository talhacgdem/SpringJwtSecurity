package com.talhacgdem.security.controller;

import com.talhacgdem.security.dto.LoginRequestDto;
import com.talhacgdem.security.entity.User;
import com.talhacgdem.security.security.JwtTokenProvider;
import com.talhacgdem.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    private final PasswordEncoder passwordEncoder;


    @PostMapping("login")
    public String login(@RequestBody LoginRequestDto loginRequestDto){
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequestDto.getUsername(), loginRequestDto.getPassword()
        );

        Authentication auth = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(auth);

        return "Bearer " + jwtTokenProvider.generateJwtToken(auth);
    }


    @PostMapping("register")
    public ResponseEntity<?> register(@RequestBody LoginRequestDto loginRequestDto){
        if (userService.getOneUserByUsername(loginRequestDto.getUsername()) != null)
            return new ResponseEntity<>("Username already taken!", HttpStatus.OK);

        User u = new User();
        u.setUsername(loginRequestDto.getUsername());
        u.setPassword(passwordEncoder.encode(loginRequestDto.getPassword()));
        return new ResponseEntity<>(userService.save(u), HttpStatus.CREATED);
    }



}
