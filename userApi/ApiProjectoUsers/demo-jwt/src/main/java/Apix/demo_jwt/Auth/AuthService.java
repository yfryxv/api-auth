package Apix.demo_jwt.Auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import Apix.demo_jwt.Jwt.JwtService;
import Apix.demo_jwt.User.User;
import Apix.demo_jwt.User.UserRepository;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginRequest request) {
        try {
            
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

            String token = jwtService.getToken(user);

            UserResponse userResponse = UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .build();

            return AuthResponse.builder()
                .token(token)
                .user(userResponse)  
                .build();
        } catch (Exception e) {
            throw new RuntimeException("Invalid email or password");
        }
    }

    public AuthResponse register(RegisterRequest request) {
        
        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
        if (existingUser.isPresent()) {
            throw new RuntimeException("Email already registered");
        }

        
        User user = User.builder()
            .name(request.getName())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .build(); 

        userRepository.save(user);

        UserResponse userResponse = UserResponse.builder()
            .id(user.getId())
            .name(user.getName())
            .email(user.getEmail())
            .build();

        return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .user(userResponse)  
            .build();
    }
}
