package com.auth.service.util;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.nio.file.Paths;

/**
 * Handle ciphering and deciphering of the token using AES-GCM.
 */

public class TokenCipher {

    /**
     * Constructor - Register AEAD configuration
     *
     * @throws Exception If any issue occurs during AEAD configuration registration
     */
    public TokenCipher() throws Exception {
        AeadConfig.register(); // Register AES-GCM configuration
    }

    /**
     * Cipher a JWT
     *
     * @param jwt          Token to cipher
     * @param keysetHandle Pointer to the keyset handle
     * @return The ciphered version of the token encoded in HEX
     * @throws Exception If any issue occurs during token ciphering operation
     */
    public String cipherToken(String jwt, KeysetHandle keysetHandle) throws Exception {
        // Verify parameters
        if (jwt == null || jwt.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("Both parameters must be specified!");
        }

        // Get the primitive
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        // Cipher the token
        byte[] cipheredToken = aead.encrypt(jwt.getBytes(), null);

        // Return the ciphered token encoded in HEX
        return DatatypeConverter.printHexBinary(cipheredToken);
    }

    /**
     * Decipher a JWT
     *
     * @param jwtInHex     Token to decipher encoded in HEX
     * @param keysetHandle Pointer to the keyset handle
     * @return The token in clear text
     * @throws Exception If any issue occurs during token deciphering operation
     */
    public String decipherToken(String jwtInHex, KeysetHandle keysetHandle) throws Exception {
        // Verify parameters
        if (jwtInHex == null || jwtInHex.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("Both parameters must be specified!");
        }

        // Decode the ciphered token from HEX
        byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

        // Get the primitive
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        // Decipher the token
        byte[] decipheredToken = aead.decrypt(cipheredToken, null);

        // Return the deciphered token as a String
        return new String(decipheredToken);
    }
}
