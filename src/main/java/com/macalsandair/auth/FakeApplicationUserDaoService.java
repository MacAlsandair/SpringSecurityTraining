package com.macalsandair.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

import static com.macalsandair.security.ApplicationUserRole.*;
import static com.macalsandair.security.ApplicationUserPermission.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		super();
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers()
					.stream()
					.filter(applicationUser -> username.equals(applicationUser.getUsername()))
					.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers () {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(
						STUDENT.getGrantedAuthorities(), passwordEncoder.encode("password"),
						"annasmith",
						true,
						true,
						true,
						true
						),
				new ApplicationUser(
						ADMIN.getGrantedAuthorities(), passwordEncoder.encode("password"),
						"linda",
						true,
						true,
						true,
						true
						),
				new ApplicationUser(
						ADMINTRAINEE.getGrantedAuthorities(), passwordEncoder.encode("password"),
						"tom",
						true,
						true,
						true,
						true
						)
				
				);
		return applicationUsers;
	}

}
