package com.springboot.jwt.security.demo.endpoint;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1/floor1")
public class FirstFloorEndpoint {

	@GetMapping("office1")
	public ResponseEntity<?> enterOffice1() {
	System.out.println("print-out :" + SecurityContextHolder.getContext().getAuthentication());
		return new ResponseEntity<>("You are inside office1", HttpStatus.OK);
	}

	@GetMapping("office2")
	@PreAuthorize("hasAnyRole('ADMIN')")
	public ResponseEntity<?> enterOffice2() {
		return new ResponseEntity<>("You are inside office2", HttpStatus.OK);
	}

}
