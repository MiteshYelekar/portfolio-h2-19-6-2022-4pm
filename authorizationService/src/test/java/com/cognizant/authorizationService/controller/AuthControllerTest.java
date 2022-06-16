package com.cognizant.authorizationService.controller;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.cognizant.authorizationService.model.UserData;
import com.fasterxml.jackson.databind.ObjectMapper;


//eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDEiLCJpYXQiOjE2NTUyMTAwODl9.UvMsaAgvRZtQ9uBjEivaygGgcd5vF-tB1sbvO_kmHiU
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
@SpringBootTest
public class AuthControllerTest {
	private static String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDEiLCJleHAiOjE2MTk5ODY4NjksImlhdCI6MTYxOTk4NTk2OX0.zL6oDqZE59jiXwP6Bj7CQtxOes5THZoEnPANn8ExBr8";
	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AuthController authController;

	@Test
	public void contextLoads() {

		assertNotNull(authController);

	}

	@Test
	public void loginTestSuccess1() throws Exception {
		UserData admin = new UserData("101", "101", "101", "101");
		ResultActions actions = mockMvc
				.perform(post("/login").contentType(MediaType.APPLICATION_JSON).content(asJsonString(admin)));
		actions.andExpect(status().isOk());
	}
	@Test
	public void loginTestSuccess2() throws Exception {
		UserData admin = new UserData("102", "102", "102", "102");
		ResultActions actions = mockMvc
				.perform(post("/login").contentType(MediaType.APPLICATION_JSON).content(asJsonString(admin)));
		actions.andExpect(status().isOk());
	}

	@Test
	public void loginTestFail() throws Exception {
		UserData admin = new UserData("randomUser", "randomUser", "randomUser","randomUser");

		ResultActions actions = mockMvc
				.perform(post("/login").contentType(MediaType.APPLICATION_JSON).content(asJsonString(admin)));
		actions.andExpect(status().isForbidden());
		actions.andExpect(status().reason("Access Denied"));
	}

	@Test
	public void validateTestSuccess() throws Exception {
		ResultActions actions = mockMvc.perform(get("/validate").header("Authorization", "Bearer " + token));

		actions.andExpect(status().isOk());

	}

	@Test
	public void validateTestFail() throws Exception {
		ResultActions actions = mockMvc.perform(get("/validate").header("Authorization", "randomToken"));

		actions.andExpect(status().isForbidden());

	}

	public static String asJsonString(UserData admin) {
		try {
			return new ObjectMapper().writeValueAsString(admin);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}