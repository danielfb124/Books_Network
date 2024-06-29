package com.db.BookSocialNetwork.auth;

import com.db.BookSocialNetwork.email.EmailService;
import com.db.BookSocialNetwork.email.EmailTemplateName;
import com.db.BookSocialNetwork.role.RoleRepository;
import com.db.BookSocialNetwork.security.JwtService;
import com.db.BookSocialNetwork.user.Token;
import com.db.BookSocialNetwork.user.TokenRepository;
import com.db.BookSocialNetwork.user.User;
import com.db.BookSocialNetwork.user.UserRepository;
import jakarta.mail.MessagingException;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    @Value("${application.mailing.frontend.activation-url}")
    private String activationUrl;

    public void register(RegistrationRequest request) throws MessagingException {
        var userRole = roleRepository.findByname("USER")
                .orElseThrow(() -> new IllegalStateException("User not found"));
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .accountLocked(false)
                .enabled(false)
                .roles(List.of(userRole))
                .build();
        userRepository.save(user);
        sendValidationEmail(user);
    }

    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user);
        emailService.sendEmail(
                user.getEmail(),
                user.fullName(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl,
                newToken,
                "Account activation"
        );

    }

    private String generateAndSaveActivationToken(User user) {
        String generatedToken= generateActivationCode(6);
        var token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();
        tokenRepository.save(token);

        return generatedToken;
}

    private String generateActivationCode(int lenght) {
        String characters="0123456789";
        StringBuilder codeBuilder=new StringBuilder();
        SecureRandom secureRandom= new SecureRandom();
        for(int i=0;i<lenght;i++){
            int randomIndex=secureRandom.nextInt(characters.length());
            codeBuilder.append(characters.charAt(randomIndex));
        }
        return  codeBuilder.toString();
    }
    }
