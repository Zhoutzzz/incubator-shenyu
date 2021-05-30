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

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * UserDetailsService example, You can override this class using database operations.
 */
public class UserService implements UserDetailsService {

    private Map<String, UserDetails> users = new HashMap<>();

    public UserService(PasswordEncoder passwordEncoder) {
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        User user = new User("testUser", passwordEncoder.encode("password"),
                Collections.singletonList(authority));
        users.put(user.getUsername(), user);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails userDetails = users.get(username);
        if (userDetails != null) {
            return userDetails;
        } else {
            throw new UsernameNotFoundException("Cannot find a user with the name of" + username);
        }
    }
}
