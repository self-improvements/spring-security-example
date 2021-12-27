package io.github.imsejin.example.googleotp.api.user.service;

import io.github.imsejin.example.googleotp.api.user.mapper.UserMapper;
import io.github.imsejin.example.googleotp.api.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper mapper;

    public User findUserById(String id) {
        return mapper.selectUserById(id);
    }

}
