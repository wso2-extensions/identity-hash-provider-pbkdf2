/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * This class contains the Client for generate PBKDF2 Hash and the Salt Value for a given plain text password.
 */
public class PBKDF2HashGenerator {

    private static final Log log = LogFactory.getLog(PBKDF2HashGenerator.class);
    private static final String SHA_1_PRNG = "SHA1PRNG";
    private static PBKDF2HashProvider pbkdf2HashProvider;

    public static void main(String[] args) {

        log.info("---Started the Hash generation Script---");
        pbkdf2HashProvider = getHashProvider();
        getPasswordFromScanner();
        log.info("---Hash generation Task Completed---");
    }

    /**
     * Get Passwords as a user input from cmd line and print hashed password and salt value.
     */
    private static void getPasswordFromScanner() {

        Scanner scanner = new Scanner(System.in, "UTF8");

        while (true) {

            log.info("Enter Password:");
            //reads password.
            String originalPassword = scanner.nextLine();

            String generatedSalt = generateSaltValue();
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
     * This private method used to create a PBKDF2HashProvider instance.
     *
     * @return pbkdf2HashProvider which is used to generate hash values.
     */
    private static PBKDF2HashProvider getHashProvider() {

        PBKDF2HashProvider pbkdf2HashProvider = new PBKDF2HashProvider();
        pbkdf2HashProvider.init();
        return pbkdf2HashProvider;
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
     * This private method returns a saltValue using SecureRandom.
     *
     * @return saltValue.
     */
    private static String generateSaltValue() throws RuntimeException {

        try {
            SecureRandom secureRandom = SecureRandom.getInstance(SHA_1_PRNG);
            byte[] bytes = new byte[16];
            //secureRandom is automatically seeded by calling nextBytes
            secureRandom.nextBytes(bytes);
            return bytesToBase64(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA1PRNG algorithm could not be found.");
        }
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
