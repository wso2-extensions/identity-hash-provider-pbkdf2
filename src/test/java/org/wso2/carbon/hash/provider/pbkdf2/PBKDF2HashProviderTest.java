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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.hash.provider.pbkdf2.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderException;

import java.util.HashMap;
import java.util.Map;

/**
 * Test class for PBKDF2HashProvider.
 */
public class PBKDF2HashProviderTest {

    private static PBKDF2HashProvider pbkdf2HashProvider = null;
    private static Map<String, Object> initProperties;

    @BeforeClass
    public void initialize() {

        pbkdf2HashProvider = new PBKDF2HashProvider();
    }

    @DataProvider(name = "initConfig")
    public Object[][] initConfig() {

        pbkdf2HashProvider.init();
        initProperties = pbkdf2HashProvider.getParameters();
        int iterationCount = (int) initProperties.get(Constants.ITERATION_COUNT_PROPERTY);
        int dkLength = (int) initProperties.get(Constants.DERIVED_KEY_LENGTH_PROPERTY);
        String pseudoRandomFunction = (String) initProperties.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY);

        return new Object[][]{
                {iterationCount, Constants.DEFAULT_ITERATION_COUNT},
                {dkLength, Constants.DEFAULT_DERIVED_KEY_LENGTH},
                {pseudoRandomFunction, Constants.DEFAULT_PBKDF2_PRF}
        };
    }

    @Test(dataProvider = "initConfig")
    public void testInitConfig(Object parameters, Object expectedValue) {

        Assert.assertEquals(parameters, expectedValue);
    }

    @DataProvider(name = "initConfigParams")
    public Object[][] initConfigParams() {

        return new Object[][]{
                {"10000", "160", "PBKDF2WithHmacSHA1"},
                {"25000", "512", "PBKDF2WithHmacSHA256"},
                {null, "256", "PBKDF2WithHmacSHA512"},
                {"10000", null, "PBKDF2WithHmacSHA256"},
                {"20000", "256", null}
        };
    }

    @Test(dataProvider = "initConfigParams")
    public void testInitConfigParams(String iterationCount, String dkLength, String pseudoRandomFunction) {

        Map<String, Object> initProperties = new HashMap<>();

        if (pseudoRandomFunction != null) {
            initProperties.put(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY, pseudoRandomFunction);
        }
        if (dkLength != null) {
            initProperties.put(Constants.DERIVED_KEY_LENGTH_PROPERTY, dkLength);
        }
        if (iterationCount != null) {
            initProperties.put(Constants.ITERATION_COUNT_PROPERTY, iterationCount);
        }
        pbkdf2HashProvider.init(initProperties);
        Map<String, Object> pbkdf2Params = pbkdf2HashProvider.getParameters();
        if (iterationCount == null) {
            Assert.assertEquals(pbkdf2Params.get(Constants.ITERATION_COUNT_PROPERTY), Constants.DEFAULT_ITERATION_COUNT);
        } else {
            Assert.assertEquals(pbkdf2Params.get(Constants.ITERATION_COUNT_PROPERTY), Integer.parseInt(iterationCount));
        }
        if (dkLength == null) {
            Assert.assertEquals(pbkdf2Params.get(Constants.DERIVED_KEY_LENGTH_PROPERTY), Constants.DEFAULT_DERIVED_KEY_LENGTH);
        } else {
            Assert.assertEquals(pbkdf2Params.get(Constants.DERIVED_KEY_LENGTH_PROPERTY), Integer.parseInt(dkLength));
        }
        if (pseudoRandomFunction == null) {
            Assert.assertEquals(pbkdf2Params.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY), Constants.DEFAULT_PBKDF2_PRF);
        } else {
            Assert.assertEquals(pbkdf2Params.get(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY), pseudoRandomFunction);
        }
    }

    @DataProvider(name = "getHash")
    public Object[][] getHash() {

        return new Object[][]{
                {"vijee123", "GzgyTT0M0TSvgMaXZEbD1Q==", "20000", "128", "PBKDF2WithHmacSHA256",
                        hexStringToByteArray("768b3558e3b5dc7bf4d5b27da4b71dee")},
                {"nisho123", "GzgyTT0M0TSvgMaXZEbD1Q==", "10000", "256", "PBKDF2WithHmacSHA256",
                        hexStringToByteArray("295fe5dbc666f75b31ff15a57b2582968a0f7dc6f53cd6799c0d0e3971626061")},
                {"john123", "GzgyTT0IOweHJgcXZEbD1Q==", "25000", "512", "PBKDF2WithHmacSHA1",
                        hexStringToByteArray("fad16c9ffc6f877b4b2cfada3596dcef4259ccaa7240c1a9ac64731b58c0c0" +
                                "d59653cf98e599f84212ea52fdcd507d7063d9601444594ff817a5de6f930ee374")}
        };
    }

    @Test(dataProvider = "getHash")
    public void testGetHash(String value, String salt, String iterationCount, String dkLength,
                            String pseudoRandomFunction, byte[] hash) throws HashProviderException {

        initProperties = new HashMap<>();
        initProperties.put(Constants.ITERATION_COUNT_PROPERTY, iterationCount);
        initProperties.put(Constants.DERIVED_KEY_LENGTH_PROPERTY, dkLength);
        initProperties.put(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY, pseudoRandomFunction);
        pbkdf2HashProvider.init(initProperties);
        Assert.assertEquals(pbkdf2HashProvider.getHash(value, salt), hash);
    }

    @DataProvider(name = "getHashWithMetaProp")
    public Object[][] getHashWithMetaProp() {

        return new Object[][]{
                {"qwerty123", 2000, 256, "PBKDF2WithHmacSHA256", "GzgyTT0M0TSvgMaXZEbD1Q==",
                        hexStringToByteArray("ef6504590bc489a7b8403ae5546b782f511c2704592124647f8a521071979243")},
                {"happy1234", null, 512, "PBKDF2WithHmacSHA1", "c4qitc/+6b0SYmVPM5YrHg==",
                        hexStringToByteArray("45e3b8ca0927d5a8a7502596a0e008614c846b6a52cfa1ce1c85095ff1e4e66a0483" +
                                "05d9e8300380c7ab6e23163c2ee11fbdc696f1350b20598646c2c5ebe530")},
                {"password", 15000, null, "PBKDF2WithHmacSHA512", "SEBcVMSL4EjBVZAvvNF3jg==",
                        hexStringToByteArray("72fcc72d1b900548d9da061340297e7de4033422c1e6eae8dff0a1e9998b1847")},
                {"hello123", 25000, 256, null, "GBeDIRPMA2tis5JwoO9c4g==",
                        hexStringToByteArray("41b26a3e614d1faf05812b51b5e8bb6c3f691a0aebe83e0ad22c7171058f8aad")}
        };
    }

    @Test(dataProvider = "getHashWithMetaProp")
    public void testGetHashWithMetaProp(String value, Object iterationCount, Object dkLength,
                                        Object pseudoRandomFunction, String salt, byte[] hash) throws HashProviderException {

        pbkdf2HashProvider.init();
        Map<String, Object> metaProperties = new HashMap<>();
        if (iterationCount != null) {
            metaProperties.put(Constants.ITERATION_COUNT_PROPERTY, iterationCount);
        }
        if (dkLength != null) {
            metaProperties.put(Constants.DERIVED_KEY_LENGTH_PROPERTY, dkLength);
        }
        if (pseudoRandomFunction != null) {
            metaProperties.put(Constants.PSEUDO_RANDOM_FUNCTION_PROPERTY, pseudoRandomFunction);
        }
        Assert.assertEquals(pbkdf2HashProvider.getHash(value, salt, metaProperties), hash);
    }

    @Test
    public void testGetAlgorithm() {

        String expectedAlgorithm = "PBKDF2";
        Assert.assertEquals(pbkdf2HashProvider.getAlgorithm(), expectedAlgorithm);
    }

    private static byte[] hexStringToByteArray(String s) {

        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
