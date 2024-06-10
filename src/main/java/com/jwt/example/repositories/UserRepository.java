package com.jwt.example.repositories;

import com.jwt.example.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {

    User findByUsername(String username);
}
