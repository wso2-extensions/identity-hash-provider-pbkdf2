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

    // Server Errors.
    ERROR_CODE_NO_SUCH_ALGORITHM("60501", "Pseudo Random Function was not detected",
            "PRF was not detected in Secret Key Factory"),
    ERROR_CODE_INVALID_KEY_SPEC("60502", "PBEKeySpec was invalid",
            "This is the exception for invalid key specifications"),
    ERROR_CODE_NULL_POINT_EXCEPTION("60503", "Null point exception at salt",
            "Salt value must not be null"),
    ERROR_CODE_ILLEGAL_ARGUEMENT_EXCEPTION("60504", "Illegal arguement of salt",
            "Salt parameter mus not be empty.");

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
