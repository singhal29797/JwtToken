package com.jwt.example.models;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Builder
@Entity
@Table(name = "user_table")
public class User {

    @Id
    private String userId;
    private String username;
    private String email;
    private String password;
    private String about;
}