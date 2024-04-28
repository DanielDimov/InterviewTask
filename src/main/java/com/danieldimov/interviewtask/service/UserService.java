package com.danieldimov.interviewtask.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.danieldimov.interviewtask.model.entity.UserEntity;
import com.danieldimov.interviewtask.model.error.ErrorEntityAlreadyExists;
import com.danieldimov.interviewtask.model.error.ErrorEntityNotActive;
import com.danieldimov.interviewtask.model.error.ErrorEntityNotFound;
import com.danieldimov.interviewtask.model.error.ErrorInvalidObject;
import com.danieldimov.interviewtask.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService {
    public static final List<String> ROLES = List.of("ADMIN", "MERCHANT", "OTHER");

    private static final Logger LOG = LoggerFactory.getLogger(UserService.class);

    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final long accessTokenValidity;
    private final long refreshTokenValidity;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, @Lazy AuthenticationManager authenticationManager, @Value("${jwt.token-secret}") String tokenSecret, @Value("${jwt.access-token-validity}") long accessTokenValidity, @Value("${jwt.refresh-token-validity}") long refreshTokenValidity) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
        this.algorithm = Algorithm.HMAC256(tokenSecret.getBytes());
        this.verifier = JWT.require(algorithm).build();
    }

    public List<String> getRoles() {
        return ROLES;
    }

    public DecodedJWT verifyToken(String token) throws JWTVerificationException {
        return verifier.verify(token);
    }

    public String generateAccessToken(UserEntity user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenValidity))
                .withClaim("permissions", user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .sign(algorithm);
    }

    public String generateRefreshToken(UserEntity user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenValidity))
                .sign(algorithm);
    }

    public UserEntity getAuthenticationUser(Authentication authentication) {
        var email = (String) authentication.getPrincipal();
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));
    }

    public UserEntity getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));
    }

    public UserEntity getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));
    }

    public UserEntity register(String email, String password) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new ErrorEntityAlreadyExists("Email is already registered!");
        }

        var user = new UserEntity();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("OTHER");
        user.setActive(false);
        return userRepository.save(user);
    }

    public UserEntity authenticate(String email, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));

        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));
    }

    public UserEntity authenticate(String token) {
        DecodedJWT jwt = verifier.verify(token);
        String email = jwt.getSubject();
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));

        if (!user.isActive()) throw new ErrorEntityNotActive("User is not active!");

        return user;
    }

    public List<UserEntity> getAllUsers() {
        return userRepository.findAll();
    }

    public boolean activate(Long userId, UserEntity authUser) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));

        if (user.isActive()) return true;

        user.setActive(true);
        userRepository.save(user);
        LOG.info("User #{} activated email '{}'.", authUser.getId(), user.getEmail());

        return true;
    }

    public boolean deactivate(Long userId, UserEntity authUser) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));

        if (!user.isActive()) return true;

        user.setActive(false);
        userRepository.save(user);
        LOG.info("User #{} deactivated email '{}'.", authUser.getId(), user.getEmail());

        return true;
    }

    public boolean setRole(Long userId, String role, UserEntity authUser) {
        if (role == null || role.isEmpty()) throw new ErrorInvalidObject("Role not provided!");

        if (!ROLES.contains(role)) throw new ErrorEntityNotFound("Role not found!");

        var user = userRepository.findById(userId)
                .orElseThrow(() -> new ErrorEntityNotFound("User not found!"));

        if (user.getRole().equals(role)) return true;

        var oldRole = user.getRole();
        user.setRole(role);
        userRepository.save(user);
        LOG.info("User #{} changed the role of email '{}' from {} to {}.", authUser.getId(), user.getEmail(), oldRole, role);

        return true;
    }


}