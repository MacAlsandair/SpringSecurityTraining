package com.macalsandair.student;

public class Student {
	
	private final Integer studentId;
	private final String name;
	public Student(Integer studentId, String name) {
		super();
		this.studentId = studentId;
		this.name = name;
	}
	public Integer getStudentId() {
		return studentId;
	}
	public String getName() {
		return name;
	}	
}
