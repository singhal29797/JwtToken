package com.jwt.example.services;

import com.jwt.example.models.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class UserService {

    private final List<User> store = new ArrayList<>();

    public List<User> getStore() {
        store.add(User.builder()
                .userId(UUID.randomUUID().toString())
                .name("Shivam Singhal")
                .designation("Engineer")
                .build());

        store.add(User.builder()
                .userId(UUID.randomUUID().toString())
                .name("Harsh Tiwari")
                .designation("Architect")
                .build());

        store.add(User.builder()
                .userId(UUID.randomUUID().toString())
                .name("Ankit Saini")
                .designation("Accountant")
                .build());

        store.add(User.builder()
                .userId(UUID.randomUUID().toString())
                .name("Satyansh Singh")
                .designation("Business Man")
                .build());

        return store;
    }
}
