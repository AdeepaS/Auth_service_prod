package com.auth.service.util;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;

import java.io.File;

public class KeyGenerator {
    public static void main(String[] args) throws Exception {
        // Register AES-GCM configuration
        AeadConfig.register();

        // Generate a new keyset for AES-GCM
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);

        // Save the keyset to a JSON file
        File keysetFile = new File("src/main/resources/certs/key-ciphering.json");
        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(keysetFile));

        System.out.println("Keyset generated and saved to: " + keysetFile.getAbsolutePath());
    }
}