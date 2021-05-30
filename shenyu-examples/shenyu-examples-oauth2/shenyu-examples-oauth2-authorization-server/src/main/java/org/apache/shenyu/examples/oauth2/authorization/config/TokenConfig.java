/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shenyu.examples.oauth2.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;


@Configuration
public class TokenConfig {

    /**
     * Symmetric key.
     */
    public static final String signingKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZEqfNZ14c" +
            "XCziHM6ds6kEp3TvaVZA4+os5Dbc14bGmN6pKBiUKofZjhAi1mzy7+4DE2EvVXgITmIzJsUZhuKf362F" +
            "vGK8j8aU3/61Oq4e3QkfyjEVR1ClB/A/5JNe60x63sN98HF4bHuiGflJnHGkzhAsiRvWBoA57LVEEgAO" +
            "TVsUOeDC9TUs6OM1XXX4q1qKNkB56Pyf2VdQwbgN+PQSkfolHyFGcPnOyYkZ0WVi6RfFK+9EgDeoRF6E" +
            "OoXSwZYcXgwtBOLyVnb/Wz2oILrfYTRUdwuzfe+Had0hBbHH2uRFvDNmYz4ApwYQnnWYHqstB8Igzoea" +
            "GFBcyXGZLSTfPsOH48tAkjwhQSWQWxmI2f4K675zS3Hd9295G9up+iOsCHPxPsOaSC0Q0X8j+6bZhMkq" +
            "AV+F1EmIfggR1watdzQqNSXOSjopzPY++dXZggW7xxx6ajBbsxjnTDQ7TU+hbWkDH0nuEw9zf4NP4eON" +
            "y1DldXcmRbo4AO8uSQxELA8= 2554136375@qq.com";

    @Bean
    public JwtAccessTokenConverter tokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(signingKey);
        return converter;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(tokenConverter());
    }
}
