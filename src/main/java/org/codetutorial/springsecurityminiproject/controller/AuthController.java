package org.codetutorial.springsecurityminiproject.controller;

import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.codetutorial.springsecurityminiproject.dto.AuthRequest;
import org.codetutorial.springsecurityminiproject.dto.RegisterRequest;
import org.codetutorial.springsecurityminiproject.model.User;
import org.codetutorial.springsecurityminiproject.repository.UserRepository;
import org.codetutorial.springsecurityminiproject.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req){
        if (userRepository.findByUsername(req.getUsername()).isPresent())
            return  ResponseEntity.badRequest().body("Username deja prix !");

        User user = new User();
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return ResponseEntity.ok("Compte cree !");
    }

    //Post /auth/login
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest req){
    authManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));

        UserDetails user = userDetailsService.loadUserByUsername(req.getUsername());
        String token = jwtService.generateToken(user);

        return ResponseEntity.ok(Map.of("token",token));

    }
}