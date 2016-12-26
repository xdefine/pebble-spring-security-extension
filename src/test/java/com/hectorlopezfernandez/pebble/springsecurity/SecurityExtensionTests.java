package com.hectorlopezfernandez.pebble.springsecurity;

import static org.hamcrest.core.StringContains.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringRunner.class)
@SpringBootTest(classes={Application.class}, webEnvironment=WebEnvironment.RANDOM_PORT)
public class SecurityExtensionTests {

	@Autowired
	private WebApplicationContext wac;
	protected MockMvc mockMvc;

	@Before
	public void setup() {
		this.mockMvc = MockMvcBuilders
			.webAppContextSetup(this.wac)
			.apply(SecurityMockMvcConfigurers.springSecurity())
			.build();
	}

	@After
	public void tearDown() {
	}

	@Test
	@WithUserDetails("admin")
	public void userIsAuthorizedByRole() throws Exception {
		this.mockMvc.perform(get("/authorized1.page"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("AUTHORIZED")));
	}
	
	@Test
	@WithUserDetails("user")
	public void userIsNotAuthorizedByRole() throws Exception {
		this.mockMvc.perform(get("/authorized1.page"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("ERROR")));
	}

	@Test
	@WithUserDetails("admin")
	public void userIsAuthorizedByUrl() throws Exception {
		this.mockMvc.perform(get("/authorized2.page"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("AUTHORIZED")));
	}

	@Test
	@WithUserDetails("user")
	public void userIsNotAuthorizedByUrl() throws Exception {
		this.mockMvc.perform(get("/authorized2.page"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("ERROR")));
	}

	@Test
	@WithUserDetails("admin")
	public void principalPrintsUserName() throws Exception {
		this.mockMvc.perform(get("/principal.page"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("admin")));
	}

}