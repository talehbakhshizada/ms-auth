package az.company.msauth.client;

import az.company.msauth.model.client.UserResponseDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "ms-user", url = "${client.ms-user.endpoint}")
public interface UserClient {
    @GetMapping("v1/user")
    UserResponseDto getUser(@RequestParam String username);
}