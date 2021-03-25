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
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This class contains the implementation of PBKDF2 hashing algorithm.
 */
public class PBKDF2HashProvider implements HashProvider {

    private static final Log log = LogFactory.getLog(PBKDF2HashProvider.class);

    private String pseudoRandomFunction;
    private int dkLength;
    private int iterationCount;

    @Override
    public void init() {

        pseudoRandomFunction = Constants.DEFAULT_PBKDF2_PRF;
        dkLength = Constants.DEFAULT_DERIVED_KEY_LENGTH;
        iterationCount = Constants.DEFAULT_ITERATION_COUNT;
    }

    @Override
    public void init(Map<String, Object> initProperties) {

        Object iterationCountObject = initProperties.get(Constants.ITERATION_COUNT_PROPERTY);
        Object dkLengthObject = initProperties.get(Constants.DERIVED_KEY_LENGTH_PROPERTY);
        Object pseudoRandomFunctionObject = initProperties.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);

        if (iterationCountObject == null) {
            iterationCount = Constants.DEFAULT_ITERATION_COUNT;
        } else {
            if (iterationCountObject instanceof String) {
                iterationCount = Integer.parseInt(iterationCountObject.toString());
            }
        }
        if (dkLengthObject == null) {
            dkLength = Constants.DEFAULT_DERIVED_KEY_LENGTH;
        } else {
            if (dkLengthObject instanceof String) {
                dkLength = Integer.parseInt(dkLengthObject.toString());
            }
        }
        if (pseudoRandomFunctionObject == null) {
            pseudoRandomFunction = Constants.DEFAULT_PBKDF2_PRF;
        } else {
            pseudoRandomFunction = (String) pseudoRandomFunctionObject;
        }
    }

    @Override
    public byte[] getHash(String value, String salt) throws HashProviderException {

        validateEmptyValue(value);
        validateEmptySalt(salt);
        return calculateHash(value, salt, pseudoRandomFunction, iterationCount, dkLength);
    }

    @Override
    public byte[] getHash(String value, String salt, Map<String, Object> metaProperties)
            throws HashProviderException {

        validateEmptyValue(value);
        validateEmptySalt(salt);
        int iterations = resolveIterationCount(metaProperties);
        int dkLen = resolveDerivedKeyLength(metaProperties);
        String prf = resolvePseudoRandomFunction(metaProperties);
        return calculateHash(value, salt, prf, iterations, dkLen);
    }

    @Override
    public Map<String, Object> getParameters() {

        Map<String, Object> pbkdf2HashProviderParams = new HashMap<>();
        pbkdf2HashProviderParams.put(Constants.ITERATION_COUNT_PROPERTY, iterationCount);
        pbkdf2HashProviderParams.put(Constants.DERIVED_KEY_LENGTH_PROPERTY, dkLength);
        pbkdf2HashProviderParams.put(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY, pseudoRandomFunction);
        return pbkdf2HashProviderParams;
    }

    @Override
    public String getAlgorithm() {

        return Constants.PBKDF2_HASHING_ALGORITHM;
    }

    /**
     * Calculate hash value according to the given parameters.
     *
     * @param value                Value to be hashed.
     * @param salt                 The salt.
     * @param pseudoRandomFunction PRF function which needs to be used for PBKDF2 hashing.
     * @param iterationCount       Number of iterations to be used by the PRF.
     * @param dkLength             The output length of the hash function.
     * @return The resulting hash value of the value.
     * @throws HashProviderException If an error occurred while calculating the hash.
     */
    private byte[] calculateHash(String value, String salt,
                                 String pseudoRandomFunction, int iterationCount, int dkLength)
            throws HashProviderException {

        try {
            validateIterationCount(iterationCount);
            validateDerivedKeyLength(dkLength);
            PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), base64ToByteArray(salt), iterationCount, dkLength);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(pseudoRandomFunction);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getDescription(), e);
            }
            throw new HashProviderServerException(ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getDescription(),
                    Constants.PBKDF2_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getCode());
        } catch (InvalidKeySpecException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getDescription(), e);
            }
            throw new HashProviderServerException(ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getDescription(),
                    Constants.PBKDF2_HASH_PROVIDER_ERROR_PREFIX +
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
                    Constants.PBKDF2_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode());
        }
    }

    /**
     * This method is responsible for validating the salt.
     *
     * @param salt The salt which needs to be validated.
     * @throws HashProviderClientException If the salt value is blank.
     */
    private void validateEmptySalt(String salt) throws HashProviderClientException {

        if (StringUtils.isBlank(salt)) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getDescription(),
                    Constants.PBKDF2_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getCode());
        }
    }

    /**
     * This method is responsible for validating the iteration count.
     *
     * @param iterationCount The iteration count needs to be validated.
     * @throws HashProviderClientException If the iteration count is negative or equal to zero.
     */
    private void validateIterationCount(int iterationCount) throws HashProviderClientException {

        if (iterationCount <= 0) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_iNVALID_ITERATION_COUNT.getDescription(),
                    Constants.PBKDF2_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_iNVALID_ITERATION_COUNT.getCode());
        }
    }

    /**
     * This method is responsible for validating the derived key length.
     *
     * @param dkLength The derived key length needs to be validated.
     * @throws HashProviderClientException If the derived key length is negative or equal to zero.
     */
    private void validateDerivedKeyLength(int dkLength) throws HashProviderClientException {

        if (dkLength <= 0) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_INVALID_DERIVED_KEY_LENGTH.getDescription(),
                    Constants.PBKDF2_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_DERIVED_KEY_LENGTH.getCode());
        }
    }

    /**
     * Resolve the iteration count according to the given meta properties.
     *
     * @param properties The properties map.
     * @return The iteration count.
     */
    private int resolveIterationCount(Map<String, Object> properties) {

        Object iterationCountObject = properties.get(Constants.ITERATION_COUNT_PROPERTY);

        if (iterationCountObject == null) {
            return iterationCount;
        }
        return (int) properties.get(Constants.ITERATION_COUNT_PROPERTY);
    }

    /**
     * Resolve derived key length from the metaProperties.
     *
     * @param properties The properties map.
     * @return The derived key length.
     */
    private int resolveDerivedKeyLength(Map<String, Object> properties) {

        Object dkLengthObject = properties.get(Constants.DERIVED_KEY_LENGTH_PROPERTY);

        if (dkLengthObject == null) {
            return dkLength;
        }
        return (int) properties.get(Constants.DERIVED_KEY_LENGTH_PROPERTY);
    }

    /**
     * Resolve pseudo random function from the metaProperties.
     *
     * @param properties The properties map.
     * @return The pseudo random function.
     */
    private String resolvePseudoRandomFunction(Map<String, Object> properties) {

        Object pseudoRandomFunctionObject = properties.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);

        if (pseudoRandomFunctionObject == null) {
            return pseudoRandomFunction;
        }
        return (String) properties.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);
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
