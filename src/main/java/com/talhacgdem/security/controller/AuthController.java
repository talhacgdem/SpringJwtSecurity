package com.talhacgdem.security.controller;

import com.talhacgdem.security.dto.LoginRequestDto;
import com.talhacgdem.security.security.JwtTokenProvider;
import com.talhacgdem.security.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthenticationManager authenticationManager;
    private JwtTokenProvider jwtTokenProvider;

    private UserService userService;


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
    }



}
