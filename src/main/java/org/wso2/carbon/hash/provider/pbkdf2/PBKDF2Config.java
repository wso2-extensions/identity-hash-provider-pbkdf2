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

import org.wso2.carbon.user.core.model.hash.Config;

/**
 * Class responsible for configurations of PBKDF2 parameters.
 */
public class PBKDF2Config implements Config {

    String name;
    String displayName;
    String description;
    String value;

    public PBKDF2Config(String name, String displayName, String description, String value) {

        this.name = name;
        this.displayName = displayName;
        this.description = description;
        this.value = value;
    }

    @Override
    public String getName() {

        return name;
    }

    @Override
    public String getDisplayName() {

        return displayName;
    }

    @Override
    public String getDescription() {

        return description;
    }

    @Override
    public String getValue() {

        return value;
    }
}
