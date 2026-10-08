/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.otp.core.util;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import javax.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MULTI_OPTION_URI_PARAM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY;

/**
 * Utility functions for the authenticator.
 */
public class AuthenticatorUtils {

    private static final Log LOG = LogFactory.getLog(AuthenticatorUtils.class);
    private static final String COMPONENT_ID = "auth-otp-core-authenticator-utils";

    /**
     * Get the multi option URI query param.
     *
     * @param request HttpServletRequest.
     * @return Query parameter for the multi option URI.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    public static String getMultiOptionURIQueryString(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter("multiOptionURI");
            multiOptionURI = multiOptionURI != null ? MULTI_OPTION_URI_PARAM +
                    Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }

    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws
            AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = AuthenticatorDataHolder
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY,
                                    AuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    FAILED_LOGIN_ATTEMPTS_PROPERTY,
                                    ACCOUNT_UNLOCK_TIME_PROPERTY
                            }, tenantDomain);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while retrieving account lock connector " +
                    "configuration for tenant : " +  tenantDomain, e);
        }
        return connectorConfigs;
    }

    /**
     * Get the parameter value from the runtime parameters if available.
     *
     * @param runtimeParams Runtime parameters.
     * @param paramName     Parameter name.
     * @return Optional parameter value.
     */
    public static Optional<String> getStringRuntimeParamByName(Map<String, String> runtimeParams,
                                                               String paramName) {

        if (MapUtils.isEmpty(runtimeParams)) {
            return Optional.empty();
        }

        String value = runtimeParams.get(paramName);
        if (StringUtils.isNotBlank(value)) {
            return Optional.of(value);
        }
        return Optional.empty();
    }

    /**
     * Get the boolean parameter value from the runtime parameters if available.
     *
     * @param runtimeParams Runtime parameters.
     * @param paramName     Parameter name.
     * @return Optional boolean parameter value.
     */
    public static Optional<Boolean> getBooleanRuntimeParamByName(Map<String, String> runtimeParams,
                                                                 String paramName) {

        Optional<String> paramValue = getStringRuntimeParamByName(runtimeParams, paramName);
        if (paramValue.isPresent()) {
            String value = paramValue.get();
            return Optional.of(Boolean.parseBoolean(value));
        }
        return Optional.empty();
    }

    /**
     * Get the integer parameter value from the runtime parameters if available.
     *
     * @param runtimeParams Runtime parameters.
     * @param paramName     Parameter name.
     * @return Optional integer parameter value.
     */
    public static OptionalInt getIntRuntimeParamByName(Map<String, String> runtimeParams,
                                                       String paramName) {

        Optional<String> value = getStringRuntimeParamByName(runtimeParams, paramName);
        if (value.isPresent()) {
            try {
                return OptionalInt.of(Integer.parseInt(value.get()));
            } catch (NumberFormatException e) {
                triggerDiagnosticLog(
                        COMPONENT_ID,
                        AuthenticatorConstants.LogConstants.ActionID.GET_OPTIONAL_INTEGER_RUNTIME_PARAMS,
                        "Unable to parse the parameter: " + paramName + " with value: "
                                + value + " to an integer. Returning empty optional.",
                        DiagnosticLog.ResultStatus.FAILED,
                        DiagnosticLog.LogDetailLevel.APPLICATION
                );
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to parse the parameter: " + paramName + " with value: "
                            + value.get() + " to an integer.", e);
                }
            }
        }
        return OptionalInt.empty();
    }

    /**
     * Trigger a diagnostic log event if diagnostic logging is enabled.
     *
     * @param componentId    The diagnostic log component ID.
     * @param actionId       The action ID associated with the log event.
     * @param message        The result message to include in the log.
     * @param status         The result status of the operation.
     * @param logDetailLevel The detail level of the log entry.
     */
    public static void triggerDiagnosticLog(String componentId, String actionId, String message,
                                            DiagnosticLog.ResultStatus status,
                                            DiagnosticLog.LogDetailLevel logDetailLevel) {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(
                    new DiagnosticLog.DiagnosticLogBuilder(componentId, actionId)
                            .resultMessage(message)
                            .logDetailLevel(logDetailLevel)
                            .resultStatus(status)
            );
        }
    }

    /**
     * This method checks if all the authentication steps up to now have been performed by authenticators that
     * implements AuthenticationFlowHandler interface. If so, it returns true.
     * AuthenticationFlowHandlers may not perform actual authentication though the authenticated user is set in the
     * context. Hence, this method can be used to determine if the user has been authenticated by a previous step.
     *
     * @param context   AuthenticationContext.
     * @return True if all the authentication steps up to now have been performed by AuthenticationFlowHandlers.
     */
    public static boolean isPreviousIdPAuthenticationFlowHandler(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        return currentAuthenticatedIdPs != null && !currentAuthenticatedIdPs.isEmpty() &&
                currentAuthenticatedIdPs.values().stream().filter(Objects::nonNull)
                        .map(AuthenticatedIdPData::getAuthenticators).filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .allMatch(authenticator ->
                                authenticator.getApplicationAuthenticator() instanceof AuthenticationFlowHandler);
    }
}
