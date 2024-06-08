package com.jwt.example.models;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Builder
public class User {

    private String userId;
    private String designation;
    private String name;
}
