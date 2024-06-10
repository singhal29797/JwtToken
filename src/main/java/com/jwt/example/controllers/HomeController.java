package com.jwt.example.controllers;

import com.jwt.example.models.User;
import com.jwt.example.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/home")
public class HomeController {

    @Autowired
    UserService userService;

    @GetMapping("/users")
    public List<User> getUser(){
        return userService.getUsers();
    }

    @GetMapping("/current-user")
    public String loggedInUser(Principal principal){
        return principal.getName();
    }
}
