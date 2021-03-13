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

/**
 * The ENUM includes all the error messages of hashing.
 */
public enum ErrorMessage {

    // Client Errors.
    ERROR_CODE_EMPTY_VALUE("60001", "Empty value", "Value cannot be empty"),
    ERROR_CODE_iNVALID_ITERATION_COUNT("60002", "Invalid iteration count",
            "Iteration count should be a positive integer"),
    ERROR_CODE_INVALID_DERIVED_KEY_LENGTH("60003", "invalid derived key length",
            "Derived key length should be a positive integer"),

    // Server Errors.
    ERROR_CODE_NO_SUCH_ALGORITHM("60501", "Not supported pseudo random function",
            "PRF was not supported by Secret Key Factory"),
    ERROR_CODE_INVALID_KEY_SPEC("60502", "Secret key cannot be generated.",
            "Secret key cannot be generated from SecretKeyFactory"),
    ERROR_CODE_EMPTY_SALT_VALUE("60503", "Invalid salt", "Salt cannot be blank");

    private final String code;
    private final String message;
    private final String description;

    ErrorMessage(String code, String message, String description) {

        this.code = code;
        this.message = message;
        this.description = description;
    }

    /**
     * Get the error code.
     *
     * @return Error code without the scenario prefix.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get error message.
     *
     * @return Error scenario message.
     */
    public String getMessage() {

        return message;
    }

    /**
     * Get error scenario description.
     *
     * @return Error scenario description.
     */
    public String getDescription() {

        return description;
    }

    @Override
    public String toString() {

        return getCode() + " | " + getMessage() + " | " + getDescription();
    }
}
