package com.macalsandair.security;

import java.util.Set;

import com.google.common.collect.Sets;
import static com.macalsandair.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
	
	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE));

	private final Set<ApplicationUserPermission> permissions;

	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}
	
	
}
