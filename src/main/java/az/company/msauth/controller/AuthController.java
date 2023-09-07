package az.company.msauth.controller;

import az.company.msauth.model.dto.SignInDto;
import az.company.msauth.model.dto.TokenDto;
import az.company.msauth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.token.TokenService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private TokenService tokenService;
    private final AuthService authService;

    @PostMapping("/sign-in")
    public TokenDto generateToken(SignInDto signInDto){
        return authService.signIn(signInDto);
    }


//    @GetMapping
//    public TokenDto refreshToken(String refreshToken){
//        return tokenService.refreshTokens(refreshToken);
//    }
//
//    @PostMapping
//    public AuthPayloadDto validateToken(String accessToken){
//        return tokenService.validateToken(accessToken);
//    }


}
