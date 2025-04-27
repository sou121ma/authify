package in.sm.authify.controller;

import in.sm.authify.io.ProfileRequest;
import in.sm.authify.io.ProfileResponse;
import in.sm.authify.service.EmailService;
import in.sm.authify.service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ProfileController {

	private final ProfileService profileService;
	private final EmailService emailService;

	@PostMapping("/register")
	@ResponseStatus(HttpStatus.CREATED)
	public ProfileResponse register(@Valid @RequestBody ProfileRequest request) {

		ProfileResponse response = profileService.createProfile(request);

		// TODO: send welcome email
		emailService.sendWelcomeEmail(response.getEmail(), response.getName());

		return response;
	}

	@GetMapping("/profile")
	public ProfileResponse getProfile(@CurrentSecurityContext(expression = "authentication?.name") String email) {
		return profileService.getProfile(email);
	}
}
