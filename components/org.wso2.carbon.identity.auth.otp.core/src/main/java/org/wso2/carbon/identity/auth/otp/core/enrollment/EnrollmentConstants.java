/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.auth.otp.core.enrollment;

/**
 * Constants related to enrolling an OTP channel value during the authentication flow.
 */
public class EnrollmentConstants {

    private EnrollmentConstants() {

    }

    // Runtime parameter which can be used from the authentication script to opt an application out.
    public static final String ENROL_USER_IN_AUTHENTICATION_FLOW = "enrolUserInAuthenticationFlow";

    // Authentication context properties, prefixed with the authenticator name.
    public static final String AWAITING_VALUE = ".enrollment.awaitingValue";
    public static final String PENDING_VALUE = ".enrollment.pendingValue";
    // Value to which the OTP in the context was sent.
    public static final String OTP_SENT_TO_VALUE = ".enrollment.otpSentToValue";
    public static final String ENROLLMENT_ATTEMPTS = ".enrollment.attempts";
    public static final String ENROLLMENT_ERROR = ".enrollment.error";

    // Suffixes of the error message keys, appended to the message key prefix of the channel.
    public static final String INVALID_VALUE_MESSAGE_SUFFIX = ".invalid";
    public static final String ENROLLMENT_FAILED_MESSAGE_SUFFIX = ".enrollment.failed";
    public static final String ATTEMPTS_EXCEEDED_MESSAGE_SUFFIX = ".enrollment.attempts.exceeded";

    public static final int DEFAULT_MAX_ENROLLMENT_ATTEMPTS = 3;
    public static final int DEFAULT_MAX_VALUE_LENGTH = 256;

    public static final String AUTH_FAILURE_QUERY_PARAMS = "&authFailure=true&authFailureMsg=";
    public static final String ENROLL_ACTION_ID = "enroll-otp-channel-value";
    public static final String ENROLLMENT_VALUE_LOG_KEY = "enrollment value";
}
