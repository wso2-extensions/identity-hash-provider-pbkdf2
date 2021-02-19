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

import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This class contains the implementation for the PBKDF2 hashing algorithm.
 */
public class PBKDF2HashProvider implements HashProvider {

    private static final Log log = LogFactory.getLog(PBKDF2HashProvider.class);

    @Override
    public byte[] getHash(String value, String salt, Map<String, Object> metaProperties)
            throws HashProviderException {

        validateEmptyValue(value);
        int iterationCount = getCount(metaProperties);
        int dkLen = getDerivedKeyLength(metaProperties);
        String pseudoRandomFunction = getPseudoRandomFunction(metaProperties);
        return pbkdf2HashCalculation(value, salt, iterationCount, dkLen, pseudoRandomFunction);
    }

    @Override
    public String getAlgorithm() {

        return Constants.DEFAULT_HASHING_ALGORITHM;
    }

    /**
     * This method is responsible for validating the value.
     *
     * @param value The value which needs to be hashed.
     * @throws HashProviderException The custom exception which is thrown at validating the value.
     */
    private void validateEmptyValue(String value) throws HashProviderException {

        if (StringUtils.isBlank(value)) {
            throw new HashProviderException(
                    ErrorMessage.ERROR_CODE_EMPTY_VALUE.getDescription(),
                    Constants.IDENTITY_HASH_PROVIDER_PBKDF2_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode());
        }
    }

    /**
     * This method is responsible for validating and getting iteration count from the metaProperties.
     *
     * @param metaProperties The Map which has the properties which needs for PBKDF2 hashing algorithm.
     * @return the iteration count which needs to be get.
     */
    private int getCount(Map<String, Object> metaProperties) {

        if (metaProperties.get(Constants.ITERATION_COUNT_KEY) == null) {
            return Constants.DEFAULT_ITERATION_COUNT;
        }
        return (int) metaProperties.get(Constants.ITERATION_COUNT_KEY);
    }

    /**
     * This method is responsible for validating and getting derived key length from the metaProperties.
     *
     * @param metaProperties The Map which has the properties which needs for PBKDF2 hashing algorithm.
     * @return the derived key length which needs to be get.
     */
    private int getDerivedKeyLength(Map<String, Object> metaProperties) {

        if (metaProperties.get(Constants.DERIVED_KEY_LENGTH_KEY) == null) {
            return Constants.DEFAULT_DERIVED_KEY_LENGTH;
        }
        return (int) metaProperties.get(Constants.DERIVED_KEY_LENGTH_KEY);
    }

    /**
     * This method is responsible for validating and getting Pseudo Random Function from the metaProperties.
     *
     * @param metaProperties The Map which has the properties which needs for PBKDF2 hashing algorithm.
     * @return the pseudo random function which needs to be get.
     */
    private String getPseudoRandomFunction(Map<String, Object> metaProperties) {

        if (metaProperties.get(Constants.PSEUDO_RANDOM_FUNCTION_KEY) == null) {
            return Constants.DEFAULT_PBKDF2_PRF;
        }
        return (String) metaProperties.get(Constants.PSEUDO_RANDOM_FUNCTION_KEY);
    }

    /**
     * This method is responsible for the implementation of PBKDF2 hashing algorithm.
     *
     * @param value                The value (eg:- Password, token) which needs to be hashed.
     * @param salt                 The salt value for each respective values.
     * @param iterationCount       Iteration count denotes how iteratively the value needs to be hashed inside PRF.
     * @param dkLen                The output length of the hash function.
     * @param pseudoRandomFunction the PRF which needs to be used in PBKDF2 hashing.
     * @return The resulting hash value of the value.
     * @throws HashProviderException This exception includes the exceptional handling for pbkdf2 hashing.
     */
    private byte[] pbkdf2HashCalculation(String value, String salt, int iterationCount, int dkLen,
                                         String pseudoRandomFunction)
            throws HashProviderException {

        try {
            PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), base64ToByteArray(salt), iterationCount, dkLen);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(pseudoRandomFunction);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getDescription(), e);
            }
            throw new HashProviderException(ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getDescription(),
                    Constants.IDENTITY_HASH_PROVIDER_PBKDF2_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getCode());
        } catch (InvalidKeySpecException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getDescription(), e);
            }
            throw new HashProviderException(ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getDescription(),
                    Constants.IDENTITY_HASH_PROVIDER_PBKDF2_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_KEY_SPEC.getCode());
        }
    }

    /**
     * this method is responsible for converting the base64 string value value of salt to byte array.
     *
     * @param salt The salt value which needs to be converted into byte array.
     * @return The converted byte array from base64 Salt value.
     */
    private byte[] base64ToByteArray(String salt) {

        byte[] name = Base64.getEncoder().encode(salt.getBytes());
        return (Base64.getDecoder().decode(new String(name).getBytes(StandardCharsets.UTF_8)));
    }

}
