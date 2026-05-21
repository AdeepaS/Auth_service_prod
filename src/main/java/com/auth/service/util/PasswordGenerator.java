package com.auth.service.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

@Component
public class PasswordGenerator {
    @Value("${password.chars.lowercase:abcdefghijklmnopqrstuvwxyz}")
    private String charLower;

    @Value("${password.chars.uppercase:ABCDEFGHIJKLMNOPQRSTUVWXYZ}")
    private String charUpper;

    @Value("${password.chars.numbers:0123456789}")
    private String numbers;

    @Value("${password.chars.special:!@#$%^&*()_-+=<>?}")
    private String special;

    @Value("${password.min.length:8}")
    private int minLength;

    @Value("${password.require.lowercase:true}")
    private boolean requireLowercase;

    @Value("${password.require.uppercase:true}")
    private boolean requireUppercase;

    @Value("${password.require.numbers:true}")
    private boolean requireNumbers;

    @Value("${password.require.special:true}")
    private boolean requireSpecial;

    private final SecureRandom random = new SecureRandom();

    public String generateRandomPassword(int length) {
        // Ensure minimum length
        if (length < minLength) {
            length = minLength;
        }

        StringBuilder password = new StringBuilder();
        List<Character> mandatoryChars = new ArrayList<>();

        // Add mandatory characters based on configuration
        if (requireLowercase && !charLower.isEmpty()) {
            mandatoryChars.add(charLower.charAt(random.nextInt(charLower.length())));
        }

        if (requireUppercase && !charUpper.isEmpty()) {
            mandatoryChars.add(charUpper.charAt(random.nextInt(charUpper.length())));
        }

        if (requireNumbers && !numbers.isEmpty()) {
            mandatoryChars.add(numbers.charAt(random.nextInt(numbers.length())));
        }

        if (requireSpecial && !special.isEmpty()) {
            mandatoryChars.add(special.charAt(random.nextInt(special.length())));
        }

        // Build the allowed characters pool
        StringBuilder allCharsBuilder = new StringBuilder();
        if (!charLower.isEmpty()) allCharsBuilder.append(charLower);
        if (!charUpper.isEmpty()) allCharsBuilder.append(charUpper);
        if (!numbers.isEmpty()) allCharsBuilder.append(numbers);
        if (!special.isEmpty()) allCharsBuilder.append(special);

        String allChars = allCharsBuilder.toString();

        if (allChars.isEmpty()) {
            throw new IllegalStateException("No character sets defined for password generation");
        }

        // Add mandatory characters first
        for (Character c : mandatoryChars) {
            password.append(c);
        }

        // Fill the rest with random characters
        for (int i = mandatoryChars.size(); i < length; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }

        // Shuffle the password
        char[] passwordArray = password.toString().toCharArray();
        for (int i = 0; i < passwordArray.length; i++) {
            int j = random.nextInt(passwordArray.length);
            char temp = passwordArray[i];
            passwordArray[i] = passwordArray[j];
            passwordArray[j] = temp;
        }

        return new String(passwordArray);
    }
}
