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

package org.apache.shenyu.examples.oauth2.authorization.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.*;

/**
 * ClientDetailsService example, You can override this class using database operations.
 */
public class ClientService implements ClientDetailsService {

    private Map<String, ClientDetails> clients = new HashMap<>();

    public ClientService(PasswordEncoder passwordEncoder) {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("shenyu");
        clientDetails.setClientSecret(passwordEncoder.encode("password"));
        clientDetails.setAuthorizedGrantTypes(Arrays.asList("password", "authorization_code", "refresh_token"));
        clientDetails.setResourceIds(Collections.singletonList("resource-server"));
        Set<String> redirectUris = new HashSet<>();
        redirectUris.add("https://dromara.org/zh/projects/soul/overview/");
        clientDetails.setRegisteredRedirectUri(redirectUris);
        clientDetails.setScope(Arrays.asList("read_userinfo", "read_contacts"));
        clients.put(clientDetails.getClientId(), clientDetails);
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        ClientDetails clientDetails = clients.get(clientId);
        if (clientDetails != null) {
            return clientDetails;
        } else {
            throw new ClientRegistrationException("A client with ID of" + clientId + "could not be found");
        }
    }
}
