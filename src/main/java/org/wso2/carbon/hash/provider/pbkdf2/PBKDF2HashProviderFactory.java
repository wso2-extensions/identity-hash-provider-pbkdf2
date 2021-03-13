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

import org.wso2.carbon.hash.provider.pbkdf2.constant.Constants;
import org.wso2.carbon.user.core.hash.HashProvider;
import org.wso2.carbon.user.core.hash.HashProviderFactory;
import org.wso2.carbon.user.core.model.hash.Config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The class contains the implementation of PBKDF2 HashProvider Factory.
 */
public class PBKDF2HashProviderFactory implements HashProviderFactory {

    @Override
    public HashProvider getHashProvider() {

        PBKDF2HashProvider pbkdf2HashProvider = new PBKDF2HashProvider();
        pbkdf2HashProvider.init();
        return pbkdf2HashProvider;
    }

    @Override
    public HashProvider getHashProvider(Map<String, Object> initProperties) {

        PBKDF2HashProvider pbkdf2HashProvider = new PBKDF2HashProvider();
        pbkdf2HashProvider.init(initProperties);
        return pbkdf2HashProvider;
    }

    @Override
    public List<Config> getHashProviderConfig() {

        List<Config> hashProviderConfig = new ArrayList<>();
        hashProviderConfig.add(new PBKDF2Config(Constants.ITERATION_COUNT_PROPERTY,
                Constants.PBKDF2_ITERATION_COUNT_DISPLAY_NAME, Constants.PBKDF2_ITERATION_COUNT_DESCRIPTION,
                Integer.toString(Constants.DEFAULT_ITERATION_COUNT)));
        hashProviderConfig.add(new PBKDF2Config(Constants.DERIVED_KEY_LENGTH_PROPERTY,
                Constants.PBKDF2_DERIVED_KEY_DISPLAY_NAME, Constants.PBKDF2_DERIVED_KEY_DESCRIPTION,
                Integer.toString(Constants.DEFAULT_DERIVED_KEY_LENGTH)));
        hashProviderConfig.add(new PBKDF2Config(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY,
                Constants.PBKDF2_PSEUDO_RANDOM_FUNCTION_DISPLAY_NAME,
                Constants.PBKDF2_PSEUDO_RANDOM_FUNCTION_DESCRIPTION, Constants.DEFAULT_PBKDF2_PRF));
        return hashProviderConfig;
    }

    @Override
    public List<String> getHashProviderMetaProperties() {

        List<String> metaProperties = new ArrayList<>();
        metaProperties.add(Constants.ITERATION_COUNT_PROPERTY);
        metaProperties.add(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);
        metaProperties.add(Constants.DERIVED_KEY_LENGTH_PROPERTY);
        return metaProperties;
    }

    @Override
    public String getType() {

        return Constants.PBKDF2_HASHING_ALGORITHM;
    }
}
