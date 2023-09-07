package az.company.msauth.service;

import az.company.msauth.client.UserClient;
import az.company.msauth.model.dto.SignInDto;
import az.company.msauth.model.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final TokenService tokenService;
    private final UserClient userClient;

    public TokenDto signIn(SignInDto signInDto){
        var user = userClient.getUser(signInDto.getUsername());
        return tokenService.generateToken(String.valueOf(user.getId()),50);
    }
}