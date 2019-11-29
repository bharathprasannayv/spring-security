package com.security.jwt.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.jwt.DTO.UserDTO;
import com.security.jwt.model.User;
import com.security.jwt.service.UserService;

import io.swagger.annotations.Api;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
public class UserController {
	@Autowired
	private UserService userService;

	@PostMapping("/signin")
	public String login(@RequestBody UserDTO user) {
		return userService.signin(user);
	}

	@PostMapping("/signup")
	public String signup(@RequestBody UserDTO user) {
		return userService.signup(user);
	}

	@DeleteMapping(value = "/{username}")
	public String delete(@PathVariable String username) {
		userService.delete(username);
		return username;
	}

	@GetMapping(value = "/{username}")
	public User search(@PathVariable String username) {
		return userService.search(username);
	}
	
	@PutMapping(value = "/update")
	public String updateUser(@RequestBody UserDTO user) {
		return userService.updateUser(user);
	}

	@GetMapping(value = "/me")
	public User whoami(HttpServletRequest req) {
		return userService.whoami(req);
	}

	@GetMapping("/refresh")
	public String refresh(HttpServletRequest req) {
		return userService.refresh(req.getRemoteUser());
	}
}
