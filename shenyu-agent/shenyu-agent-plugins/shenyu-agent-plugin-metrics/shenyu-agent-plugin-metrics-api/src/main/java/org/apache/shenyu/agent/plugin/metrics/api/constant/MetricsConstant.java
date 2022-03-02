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

package org.apache.shenyu.agent.plugin.metrics.api.constant;

/**
 * The type Metrics constant.
 */
public final class MetricsConstant {

    /**
     * The constant PROMETHEUS.
     */
    public static final String PROMETHEUS = "prometheus";

    /**
     * The constant REQUEST_TOTAL.
     */
    public static final String REQUEST_TOTAL = "shenyu_request_total";

    /**
     * The constant REQUEST_THROW_TOTAL.
     */
    public static final String REQUEST_THROW_TOTAL = "shenyu_request_throw_total";

    /**
     * The constant REQUEST_THROW_TOTAL.
     */
    public static final String HTTP_REQUEST_TOTAL = "shenyu_http_request_total";

    /**
     * The constant SHENYU_REQUEST_UNDONE.
     */
    public static final String SHENYU_REQUEST_UNDONE = "shenyu_request_undone";

    /**
     * The constant SHENYU_EXECUTE_LATENCY_MILLIS.
     */
    public static final String SHENYU_EXECUTE_LATENCY_MILLIS = "shenyu_execute_latency_millis";

}