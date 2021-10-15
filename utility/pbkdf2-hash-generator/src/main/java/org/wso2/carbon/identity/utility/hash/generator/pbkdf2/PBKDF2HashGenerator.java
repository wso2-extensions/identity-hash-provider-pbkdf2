/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.utility.hash.generator.pbkdf2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.hash.provider.pbkdf2.PBKDF2HashProvider;
import org.wso2.carbon.user.core.exceptions.HashProviderException;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

/**
 * This class contains the client for generate PBKDF2 hash and the salt value for a given plain text password.
 */
public class PBKDF2HashGenerator {

    private static final Log log = LogFactory.getLog(PBKDF2HashGenerator.class);
    private static final String SHA_1_PRNG = "SHA1PRNG";
    private static PBKDF2HashProvider pbkdf2HashProvider;

    public static void main(String[] args) {

        log.info("---Started the Hash generation Script---");
        initHashProvider();
        getPasswordFromScanner();
        log.info("---Hash generation Task Completed---");
    }

    /**
     * Get passwords as a user input from command line and print hashed password and salt value.
     */
    private static void getPasswordFromScanner() {

        Scanner scanner = new Scanner(System.in, "UTF8");

        while (true) {

            log.info("Enter Password:");
            // Reads password from scanner.
            String originalPassword = scanner.nextLine();
            String generatedSalt;
            try {
                generatedSalt = generateSaltValue();
            } catch (NoSuchAlgorithmException e) {
                log.error(e);
                break;
            }
            byte[] generatedSecuredPasswordHash;
            try {
                generatedSecuredPasswordHash = calculateHash(originalPassword.toCharArray(), generatedSalt);
            } catch (HashProviderException e) {
                log.error(e);
                break;
            }
            String strongPassword = bytesToBase64(generatedSecuredPasswordHash);

            log.info("Hashed Password:" + strongPassword);
            log.info("Salt Value:" + generatedSalt);
            log.info("----------------------------------");
        }
    }

    /**
     * This method used to initialize the PBKDF2 hash provider instance.
     */
    private static void initHashProvider() {

        pbkdf2HashProvider = new PBKDF2HashProvider();
        pbkdf2HashProvider.init();
    }

    /**
     * Generate hash password for the given plain password and salt value.
     *
     * @param plainText The plain text value to be hashed.
     * @param salt      The salt value.
     * @return The resulting hash value of the value.
     */
    private static byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {

        return pbkdf2HashProvider.calculateHash(plainText, salt);
    }

    /**
     * This private method returns a salt value using SecureRandom.
     *
     * @return Salt value.
     * @throws NoSuchAlgorithmException If no provider supports SecureRandom implementation for the specified algorithm.
     */
    private static String generateSaltValue() throws NoSuchAlgorithmException {

        SecureRandom secureRandom = SecureRandom.getInstance(SHA_1_PRNG);
        byte[] bytes = new byte[16];
        // Secure random is automatically seeded by calling next bytes.
        secureRandom.nextBytes(bytes);
        return bytesToBase64(bytes);
    }

    /**
     * This method is responsible for converting the byte array of salt to a base64 string value.
     *
     * @param bytes The byte array.
     * @return The converted base64 string value from byte array.
     */
    private static String bytesToBase64(byte[] bytes) {

        byte[] byteArray = Base64.getEncoder().encode(bytes);
        return (new String(byteArray, StandardCharsets.UTF_8));
    }
}
