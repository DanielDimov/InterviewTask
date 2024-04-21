package com.danieldimov.interviewtask.configuration;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.danieldimov.interviewtask.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.server.PathContainer;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import static com.danieldimov.interviewtask.InterviewTaskApplication.API_URL_PATTERN;
import static com.danieldimov.interviewtask.InterviewTaskApplication.OPEN_URLS;
import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    public static final String TOKEN_PREFIX = "Bearer ";

    private final UserService userService;
    private final UserDetailsService userDetailsService;
    private final List<PathPattern> openURLs;
    private final PathPattern apiPattern;

    public JwtAuthenticationFilter(UserService userService, UserDetailsService userDetailsService) {
        this.userService = userService;
        this.userDetailsService = userDetailsService;
        openURLs = stream(OPEN_URLS)
                .map(PathPatternParser.defaultInstance::parse)
                .toList();
        apiPattern = PathPatternParser.defaultInstance.parse(API_URL_PATTERN);
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        var uri = request.getRequestURI();
        var pc = PathContainer.parsePath(uri);

        // Open URLs and all FE URLs will be passed through without any processing
        var isOpen = openURLs.stream().anyMatch(pp -> pp.matches(pc));
        var isAPI = apiPattern.matches(pc);
        if (isOpen || !isAPI) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader == null) {
            response.sendError(401);
            return;
        }

        if (!authorizationHeader.startsWith(TOKEN_PREFIX)) {
            response.sendError(401);
            return;
        }

        String token = authorizationHeader.substring(TOKEN_PREFIX.length());
        try {
            DecodedJWT decodedJWT = userService.verifyToken(token);
            String username = decodedJWT.getSubject();
            if (username == null) {
                // valid token, but without username attribute
                response.sendError(401);
                return;
            }

            var user = userDetailsService.loadUserByUsername(username);
            if (!user.isEnabled() || !user.isAccountNonLocked()) {
                // valid user, but the user is inactive
                response.sendError(401);
                return;
            }

            if (decodedJWT.getExpiresAt().before(new Date())) {
                // expired token
                response.sendError(401);
                return;
            }

            String[] permissions = decodedJWT.getClaim("permissions").asArray(String.class);
            if (permissions == null) {
                response.sendError(401);
                return;
            }

            var roles = stream(permissions)
                    .filter(p -> p.startsWith("ROLE_"))
                    .map(SimpleGrantedAuthority::new)
                    .toList();
            var authenticationToken = new UsernamePasswordAuthenticationToken(username, null, roles);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            filterChain.doFilter(request, response);
        } catch (JWTVerificationException ex) {
            response.sendError(401);
        }
    }
}