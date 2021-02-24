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

package org.wso2.carbon.hash.provider.pbkdf2;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.hash.provider.pbkdf2.constant.Constants;

import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.exceptions.HashProviderServerException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This class contains the implementation of PBKDF2 hashing algorithm.
 */
public class PBKDF2HashProvider implements HashProvider {

    private static final Log log = LogFactory.getLog(PBKDF2HashProvider.class);

    @Override
    public byte[] getHash(String value, String salt, Map<String, Object> metaProperties)
            throws HashProviderException {

        validateEmptyValue(value);
        int iterationCount = resolveIterationCount(metaProperties);
        int dkLen = resolveDerivedKeyLength(metaProperties);
        String pseudoRandomFunction = resolvePseudoRandomFunction(metaProperties);
        return pbkdf2HashCalculation(value, salt, iterationCount, dkLen, pseudoRandomFunction);
    }

    @Override
    public String getAlgorithm() {

        return Constants.DEFAULT_HASHING_ALGORITHM;
    }

    /**
     * Calculate hash value according to the given parameters.
     *
     * @param value                Value to be hashed.
     * @param salt                 The salt.
     * @param iterationCount       Number of iterations to be used by the PRF.
     * @param dkLength             The output length of the hash function.
     * @param pseudoRandomFunction PRF function which needs to be used for PBKDF2 hashing.
     * @return The resulting hash value of the value.
     * @throws HashProviderException If an error occurred while calculating the hash.
     */
    private byte[] pbkdf2HashCalculation(String value, String salt, int iterationCount, int dkLength,
                                         String pseudoRandomFunction)
            throws HashProviderException {

        try {
            validateSalt(salt);
            PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), base64ToByteArray(salt), iterationCount, dkLength);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(pseudoRandomFunction);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getDescription(), e);
            }
            throw new HashProviderServerException(ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getDescription(),
                    Constants.IDENTITY_HASH_PROVIDER_PBKDF2_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getCode());
        } catch (InvalidKeySpecException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getDescription(), e);
            }
            throw new HashProviderServerException(ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getDescription(),
                    Constants.IDENTITY_HASH_PROVIDER_PBKDF2_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getCode());
        }
    }

    /**
     * This method is responsible fpr validating the value to be hashed.
     *
     * @param value The value which needs to be hashed.
     * @throws HashProviderClientException If the hash value is not provided.
     */
    private void validateEmptyValue(String value) throws HashProviderClientException {

        if (StringUtils.isBlank(value)) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_EMPTY_VALUE.getDescription(),
                    Constants.IDENTITY_HASH_PROVIDER_PBKDF2_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode());
        }
    }

    /**
     * This method is responsible for validating the salt.
     *
     * @param salt The salt which needs to be validated.
     * @throws HashProviderClientException If the salt value is blank.
     */
    private void validateSalt(String salt) throws HashProviderClientException {

        if (StringUtils.isBlank(salt)) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_SALT_EMPTY_EXCEPTION.getDescription(),
                    Constants.IDENTITY_HASH_PROVIDER_PBKDF2_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode());
        }
    }

    /**
     * Resolve the iteration count according to the given meta properties.
     *
     * @param metaProperties The properties map.
     * @return The iteration count.
     */
    private int resolveIterationCount(Map<String, Object> metaProperties) {

        if (metaProperties.get(Constants.ITERATION_COUNT_PROPERTY) == null) {
            return Constants.DEFAULT_ITERATION_COUNT;
        }
        return (int) metaProperties.get(Constants.ITERATION_COUNT_PROPERTY);
    }

    /**
     * Resolve derived key length from the metaProperties.
     *
     * @param metaProperties The properties map.
     * @return The derived key length.
     */
    private int resolveDerivedKeyLength(Map<String, Object> metaProperties) {

        if (metaProperties.get(Constants.DERIVED_KEY_LENGTH_PROPERTY) == null) {
            return Constants.DEFAULT_DERIVED_KEY_LENGTH;
        }
        return (int) metaProperties.get(Constants.DERIVED_KEY_LENGTH_PROPERTY);
    }

    /**
     * Resolve pseudo random function from the metaProperties.
     *
     * @param metaProperties The properties map.
     * @return The pseudo random function.
     */
    private String resolvePseudoRandomFunction(Map<String, Object> metaProperties) {

        if (metaProperties.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY) == null) {
            return Constants.DEFAULT_PBKDF2_PRF;
        }
        return (String) metaProperties.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);
    }

    /**
     * This method is responsible for converting the base64 string value value of salt to byte array.
     *
     * @param salt The salt.
     * @return The converted byte array from base64 salt value.
     */
    private byte[] base64ToByteArray(String salt) {

        byte[] name = Base64.getEncoder().encode(salt.getBytes());
        return (Base64.getDecoder().decode(new String(name).getBytes(StandardCharsets.UTF_8)));
    }
}
