/*
 * Copyright (c) 2023-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.otp.core;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.auth.otp.core.model.OTPResendClaims;
import org.wso2.carbon.identity.auth.otp.core.util.AuthenticatorUtils;
import org.wso2.carbon.identity.captcha.connector.recaptcha.SSOLoginReCaptchaConfig;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.captcha.util.CaptchaUtil;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.IS_IDF_INITIATED_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AUTHENTICATORS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AUTHENTICATORS_QUERY_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.LOGOUT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.SUBMIT_OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.CODE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.Claims.ACCOUNT_UNLOCK_TIME_CLAIM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_LENGTH;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_VALIDITY_IN_MILLIS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_CODE_MISSING_SMS_SENDER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_USER_CLAIM_NOT_FOUND_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_USER_MOBILE_NUMBER_MISSING;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_USERNAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_CHECKING_USER_EXISTENCE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_LAST_RESEND_TIME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_OTP_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_CLAIM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_TRIGGERING_EVENT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_UPDATING_USER_CLAIMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_GETTING_ACCOUNT_STATE;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_FEDERATED_USER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_MOBILE_NUMBER_FOUND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_USER_FOUND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_OTP_EXPIRED;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_OTP_INVALID;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_RESEND_LIMIT_EXCEEDED;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_RETRYING_OTP_RESEND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_USER_ACCOUNT_LOCKED;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.FAILED_LOGIN_ATTEMPTS_CLAIM_URI;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.HIDE_USER_EXISTENCE_CONFIG;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.IDF_HANDLER_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.INVALID_USERNAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.IS_LOGIN_ATTEMPT_BY_INVALID_USER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.LOCAL_AUTHENTICATOR;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MAXIMUM_RESEND_LIMIT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.MAXIMUM_ALLOWED_FAILURE_LIMIT;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP_ALPHA_NUMERIC_CHAR_SET;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.OTP_NUMERIC_CHAR_SET;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.RECAPTCHA_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.RESEND;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.RETRY_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.ERROR_CODE_QUERY_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.SCREEN_VALUE_QUERY_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.TERMINATE_ON_RESEND_LIMIT_EXCEEDED;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.UNKNOWN_USER;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.UNLOCK_QUERY_PARAM;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.USERNAME;
import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.USERNAME_PARAM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OPERATION_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * This class contains the implementation of abstract OTP authenticator.
 */
public abstract class AbstractOTPAuthenticator extends AbstractApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(AbstractOTPAuthenticator.class);

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        AuthenticatorConstants.AuthenticationScenarios scenario = resolveScenario(request, context);
        switch (scenario) {
            case LOGOUT:
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            case INITIAL_OTP:
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            default:
                // Resend OTP and Submit OTP processing will be handled from here.
                return super.process(request, response, context);
        }
    }

    /**
     * Get OTP resend related identity claims.
     *
     * @return OTPResendClaims object containing the claim URIs.
     */
    protected OTPResendClaims getOTPResendClaims() {

        throw new NotImplementedException("User based OTP resend blocking is not supported.");
    }

    /**
     * Get OTP resend block duration in minutes.
     *
     * @param tenantDomain Tenant domain.
     * @return Block duration in minutes.
     * @throws AuthenticationFailedException If an error occurs while getting the block duration.
     */
    protected int getOTPResendBlockDuration(String tenantDomain) throws AuthenticationFailedException {

        throw new NotImplementedException("User based OTP resend blocking is not supported.");
    }

    /**
     * Check whether context based OTP resend blocking is enabled.
     *
     * @param context Authentication context.
     * @return true if enabled, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while checking the configuration.
     */
    protected boolean isContextBasedOTPResendBlockingEnabled(AuthenticationContext context)
            throws AuthenticationFailedException {

        OptionalInt maximumAllowedResendAttemptsLimit =
                AuthenticatorUtils.getIntRuntimeParamByName(getRuntimeParams(context),
                        MAXIMUM_RESEND_LIMIT);
        if (maximumAllowedResendAttemptsLimit.isPresent()) {
            int resendLimit = maximumAllowedResendAttemptsLimit.getAsInt();
            if (resendLimit >= 0) {
                return true;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Invalid value: %d for maximum allowed resend attempts limit. " +
                                "The value should be a non-negative integer.",
                        resendLimit));
            }
            AuthenticatorUtils.triggerDiagnosticLog(getName(),
                    AuthenticatorConstants.LogConstants.ActionID.GET_MAX_RESEND_LIMIT,
                    "Invalid value: " + resendLimit + " for maximum allowed resend attempts limit. " +
                            "The value should be a non-negative integer.",
                    DiagnosticLog.ResultStatus.FAILED,
                    DiagnosticLog.LogDetailLevel.APPLICATION
            );
        }
        return false;
    }

    /**
     * Check whether context based retry blocking is enabled.
     *
     * @return true if enabled, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while checking the configuration.
     */
    protected boolean isContextBasedRetryBlockingEnabled(AuthenticationContext context)
            throws AuthenticationFailedException {

        OptionalInt maximumAllowedRetryAttemptsLimit =
                AuthenticatorUtils.getIntRuntimeParamByName(getRuntimeParams(context),
                        MAXIMUM_ALLOWED_FAILURE_LIMIT);
        if (maximumAllowedRetryAttemptsLimit.isPresent()) {
            int retryLimit = maximumAllowedRetryAttemptsLimit.getAsInt();
            if (retryLimit > 0) {
                return true;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        String.format("Invalid value: %d for maximum allowed retry attempts limit. " +
                                "The value should be a positive integer.", retryLimit));
            }
            AuthenticatorUtils.triggerDiagnosticLog(getName(),
                    AuthenticatorConstants.LogConstants.ActionID.GET_MAX_FAILURE_LIMIT,
                    "Invalid value: " + retryLimit + " for maximum allowed failure attempts limit. " +
                            "The value should be a positive integer.",
                    DiagnosticLog.ResultStatus.FAILED,
                    DiagnosticLog.LogDetailLevel.APPLICATION
            );
        }
        return false;
    }

    /**
     * Check whether the authentication flow should be terminated when the OTP resend limit is exceeded.
     *
     * @return true if the flow should be terminated, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while checking the configuration.
     */
    protected boolean isTerminateOnResendLimitExceeded(AuthenticationContext context)
            throws AuthenticationFailedException {

        Optional<Boolean> terminateOnResendLimitExceededParam =
                AuthenticatorUtils.getBooleanRuntimeParamByName(getRuntimeParams(context),
                        TERMINATE_ON_RESEND_LIMIT_EXCEEDED);
        return terminateOnResendLimitExceededParam.isPresent() && terminateOnResendLimitExceededParam.get();
    }

    /**
     * Check whether user based OTP resend blocking is enabled.
     *
     * @return true if enabled, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while checking the configuration.
     */
    protected boolean isUserBasedOTPResendBlockingEnabled() throws AuthenticationFailedException {

        return false;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        String applicationTenantDomain = context.getTenantDomain();
        AuthenticatorConstants.AuthenticationScenarios scenario = resolveScenario(request, context);

        String otpAlreadySentInFlowKey = getName() + ".otpAlreadySentInFlow";
        if (scenario == INITIAL_OTP && Boolean.TRUE.equals(context.getProperty(otpAlreadySentInFlowKey))) {
            scenario = RESEND_OTP;
        }

        /*
         * If an invalid user has attempted to log in by submitting an OTP code, or if an invalid user has requested
         * to resend the OTP code, they should be redirected to the OTP login page. This is only valid when OTP is
         * set as the first step of the authentication flow because in other cases, there will always be a valid user in
         * the context.
         */
        if (isLoginAttemptByInvalidUser(context, authenticatedUserFromContext)) {
            AuthenticatedUser invalidUser = new AuthenticatedUser();
            invalidUser.setUserName((String) context.getProperty(INVALID_USERNAME));
            if (isOTPResendLimitExceededScenario(scenario, false , context)) {
                handleOTPResendCountExceededScenario(request, response, context, invalidUser);
                return;
            } else if (scenario == RESEND_OTP) {
                updateContextOTPResendCount(context);
            }
            redirectToOTPLoginPage(invalidUser, applicationTenantDomain, false,
                    response, request, context);
            return;
        }
        if (this instanceof PasswordlessOTPAuthenticator && isAuthenticatorEnabledForFirstFactor()) {
            if (authenticatedUserFromContext == null) {
                /*
                 * If there is no authenticated user, and the request is not returned from the Identifier First page,
                 * redirect the user to the Identifier First page to retrieve the username.
                 */
                if (!isUserRedirectedFromIDF(request)) {
                    redirectUserToIDF(request, response, context);
                    context.setProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                    return;
                }
                // If the request is returned from the Identifier First page, resolve the user and set them in context.
                context.removeProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR);
                AuthenticatedUser authenticatedUser = resolveUserFromRequest(request, context);
                try {
                    authenticatedUserFromContext = resolveUserFromUserStore(authenticatedUser, context);
                } catch (AuthenticationFailedException e) {
                    // Check if the exception is specifically about multiple users
                    if (e.getMessage() != null &&
                            e.getMessage().contains(AuthenticatorConstants.MULTIPLE_USERS_ERROR_MESSAGE)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Multiple users found for the provided username", e);
                        }

                        if (isOTPAsFirstFactor(context) &&
                                Boolean.parseBoolean(IdentityUtil.getProperty(AuthenticatorConstants.HIDE_USER_EXISTENCE_CONFIG))) {
                            if (isOTPResendLimitExceededScenario(scenario, false, context)) {
                                handleOTPResendCountExceededScenario(request, response, context, null);
                                return;
                            } else if (scenario == RESEND_OTP) {
                                updateContextOTPResendCount(context);
                            }
                            redirectToOTPLoginPage(authenticatedUser, applicationTenantDomain, false, response, request, context);
                            return;
                        }
                    }
                    throw e;
                }
                setResolvedUserInContext(context, authenticatedUserFromContext);
            } else if (AuthenticatorUtils.isPreviousIdPAuthenticationFlowHandler(context)) {
                /*
                 * If the previous authentication has only been done by AuthenticationFlowHandlers, need to check if the
                 * user exists in the database.
                 */
                authenticatedUserFromContext = resolveUserFromUserStore(authenticatedUserFromContext, context);
                setResolvedUserInContext(context, authenticatedUserFromContext);
            }
             // If the authenticated user is still null at this point, then an invalid user is trying to log in.
            if (authenticatedUserFromContext == null) {
                AuthenticatedUser invalidUser = new AuthenticatedUser();
                invalidUser.setUserName(request.getParameter(USERNAME));
                context.setProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER, true);
                context.setProperty(INVALID_USERNAME, request.getParameter(USERNAME));
                if (isOTPResendLimitExceededScenario(scenario, false, context)) {
                    handleOTPResendCountExceededScenario(request, response, context, invalidUser);
                    return;
                } else if (scenario == RESEND_OTP) {
                    updateContextOTPResendCount(context);
                }
                redirectToOTPLoginPage(invalidUser, applicationTenantDomain, false,
                        response, request, context);
                return;
            }
        }

        /*
         * If we reach this point, a valid user is trying to log in.
         */
        context.removeProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER);
        context.removeProperty(INVALID_USERNAME);

        /*
         * We need to identify the username that the server is using to identify the user. This is needed to handle
         * federated scenarios, since for federated users, the username in the authentication context is not same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt);
        try {
            if (!isInitialFederationAttempt
                && AuthenticatorDataHolder.getAccountLockService().isAccountLocked(
                    authenticatingUser.getUserName(),
                    authenticatingUser.getTenantDomain(),
                    authenticatingUser.getUserStoreDomain())
            ) {
                handleOTPForLockedUser(authenticatingUser, request, response, context);
                return;
            }
        } catch (AccountLockServiceException e) {
            String error = String.format(
                    ERROR_CODE_GETTING_ACCOUNT_STATE.getMessage(),
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
            throw new AuthenticationFailedException(ERROR_CODE_GETTING_ACCOUNT_STATE.getCode(), error, e);
        }
        OTPResendClaims otpResendClaims = null;
        int otpResendCount = 0;
        boolean shouldUpdateUserClaim = false;
        AuthenticatedUser mappedLocalUser =
                authenticatedUserFromContext.isFederatedUser() ? authenticatingUser :
                        authenticatedUserFromContext;
        boolean isUserExists = isUserExists(mappedLocalUser, context);
        if (scenario == INITIAL_OTP || scenario == RESEND_OTP) {
            int allowedResendAttemptsCountForUserBeforeBlock = getMaximumResendAttempts(applicationTenantDomain);
            boolean isUserBasedOTPResendBlockingEnabled = isUserBasedOTPResendBlockingEnabled() && isUserExists;
            if (isUserBasedOTPResendBlockingEnabled) {
                otpResendClaims = getOTPResendClaims();

                // Get user-specific resend attempt count
                String userResendCountStr =
                        getUserClaimValueFromUserStore(
                                otpResendClaims.getResendAttemptClaimUri(),
                                mappedLocalUser,
                                ERROR_CODE_ERROR_GETTING_OTP_RESEND_ATTEMPTS);
                if (StringUtils.isNotBlank(userResendCountStr)) {
                    otpResendCount = Integer.parseInt(userResendCountStr);
                }

                // Get last successful resend timestamp (if any)
                String lastResendTimestamp = getUserClaimValueFromUserStore(
                        otpResendClaims.getLastResendTimeClaimUri(),
                        mappedLocalUser,
                        ERROR_CODE_ERROR_GETTING_LAST_RESEND_TIME);
                if (otpResendCount >= allowedResendAttemptsCountForUserBeforeBlock) {
                    // Convert block time (minutes) to milliseconds
                    int otpResendBlockTimeMinutes = getOTPResendBlockDuration(applicationTenantDomain);
                    if (StringUtils.isNotBlank(lastResendTimestamp)) {
                        long lastResend = Long.parseLong(lastResendTimestamp);
                        long now = System.currentTimeMillis();
                        long blockTimeMillis = otpResendBlockTimeMinutes * 60_000L; // MINUTES → MILLIS
                        boolean withinBlockWindow = (now - lastResend) < blockTimeMillis;

                        if (withinBlockWindow) {
                            // If the user is within the block window, do not terminate the flow immediately.
                            // Instead, redirect the user to the OTP login page with an error message indicating
                            // that the resend limit has been exceeded.
                            handleOTPResendCountExceededScenario(request, response, context, authenticatingUser, false);
                            return;
                        } else {
                            otpResendCount = 0;
                            shouldUpdateUserClaim = true;
                        }
                    }
                }
                if (scenario == RESEND_OTP) {
                    otpResendCount++;
                    shouldUpdateUserClaim = true;
                }
            }

            if (isOTPResendLimitExceededScenario(scenario, isUserBasedOTPResendBlockingEnabled, context)) {
                handleOTPResendCountExceededScenario(request, response, context, authenticatingUser);
                return;
            } else if (scenario == RESEND_OTP) {
                updateContextOTPResendCount(context);
            }
            OTP otp = generateOTP(applicationTenantDomain);
            context.setProperty(OTP, otp);

            /*
             * Here we need to pass the authenticated user as the authenticated user from context since the events needs
             * to triggered against the context user.
             */
            try {
                sendOtp(mappedLocalUser, otp, isInitialFederationAttempt, request, response, context);
                LOG.debug("OTP code was sent successfully.");
                context.setProperty(getName() + ".otpAlreadySentInFlow", true);
            } catch (AuthenticationFailedException exception) {
                String errorGettingUserClaimErrorCode = getAuthenticatorErrorPrefix() + "-"
                        + ERROR_CODE_ERROR_GETTING_USER_CLAIM.getCode();
                String errorUserMobileNumberMissing = getAuthenticatorErrorPrefix() + "-"
                        + ERROR_CODE_NO_MOBILE_NUMBER_FOUND.getCode();
                if (errorGettingUserClaimErrorCode.equals(exception.getErrorCode())) {
                    if (isOTPAsFirstFactor(context)) {
                        redirectToOTPLoginPage(authenticatedUserFromContext, applicationTenantDomain,
                                isInitialFederationAttempt, response, request, context);
                    } else {
                        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                                context.getQueryParams(), context.getCallerSessionKey(),
                                context.getContextIdentifier());
                        redirectToErrorPage(request, response, context, queryParams,
                                ERROR_USER_CLAIM_NOT_FOUND_QUERY_PARAMS);
                    }
                    return;
                } else if (errorUserMobileNumberMissing.equals(exception.getErrorCode())) {
                    boolean hideUserExistence = Boolean.parseBoolean((String) IdentityConfigParser.getInstance()
                            .getConfiguration().get(HIDE_USER_EXISTENCE_CONFIG));
                    if (!isOTPAsFirstFactor(context) || !hideUserExistence) {
                        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                                context.getQueryParams(), context.getCallerSessionKey(),
                                context.getContextIdentifier());
                        redirectToErrorPage(request, response, context, queryParams, ERROR_USER_MOBILE_NUMBER_MISSING);
                        return;
                    }
                } else {
                    throw exception;
                }
            }

            if (isUserBasedOTPResendBlockingEnabled) {
                if (shouldUpdateUserClaim) {
                    Map<String, String> claimMap = new HashMap<>();
                    claimMap.put(otpResendClaims.getResendAttemptClaimUri(), String.valueOf((otpResendCount)));
                    claimMap.put(otpResendClaims.getLastResendTimeClaimUri(),
                            String.valueOf(System.currentTimeMillis()));
                    setUserClaimValueFromUserStore(claimMap, mappedLocalUser);
                }
            }

            publishPostOTPGeneratedEvent(otp, authenticatedUserFromContext, request, context);
        }
        redirectToOTPLoginPage(mappedLocalUser, applicationTenantDomain, isInitialFederationAttempt,
                response, request, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        String applicationTenantDomain = context.getTenantDomain();
        boolean isResendAttempt = Boolean.parseBoolean(request.getParameter(RESEND));

        // If the scenario is a resend let the invalid login scenario handled from initiateAuthenticationRequest method.
        if (authenticatedUserFromContext == null) {
            if (isResendAttempt) {
                throw handleInvalidCredentialsScenario(ERROR_CODE_RETRYING_OTP_RESEND,
                        AuthenticatorUtils.maskIfRequired((String) context.getProperty(INVALID_USERNAME)));
            }
            handleInvalidOTPLoginAttempt(context, applicationTenantDomain);
            throw handleAuthErrorScenario(ERROR_CODE_NO_USER_FOUND);
        }
        /*
         * We need to identify the username that the server is using to identify the user. This is needed to handle
         * federated scenarios, since for federated users, the username in the authentication context is not same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt);
        try {
            if (!isInitialFederationAttempt
                    && AuthenticatorDataHolder.getAccountLockService().isAccountLocked(
                    authenticatingUser.getUserName(), authenticatingUser.getTenantDomain(),
                    authenticatingUser.getUserStoreDomain())) {
                throw handleAuthErrorScenario(ERROR_CODE_USER_ACCOUNT_LOCKED,
                        AuthenticatorUtils.maskIfRequired(authenticatingUser.getUserName()));
            }
        } catch (AccountLockServiceException e) {
            throw handleAuthErrorScenario(ERROR_CODE_GETTING_ACCOUNT_STATE, e);
        }

        /* If user requests a resend, throw error */
        if (isResendAttempt) {
            throw handleInvalidCredentialsScenario(ERROR_CODE_RETRYING_OTP_RESEND,
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
        }
        /* If an empty code is received, throw error. */
        if (StringUtils.isBlank(request.getParameter(CODE))) {
            handleInvalidOTPLoginAttempt(context, applicationTenantDomain);
            throw handleInvalidCredentialsScenario(ERROR_CODE_EMPTY_OTP_CODE,
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
        }
        boolean isSuccessfulAttempt = isSuccessfulAuthAttempt(request.getParameter(CODE), authenticatingUser, context);
        OTP otpInContext = (OTP) context.getParameter(OTP);
        if (isSuccessfulAttempt) {
            // It reached here means the authentication was successful.
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("User: %s authenticated successfully via OTP",
                        authenticatedUserFromContext.getUserName()));
            }
            if (!isInitialFederationAttempt) {
                // A mapped user is not available for isInitialFederationAttempt true scenario.
                resetOtpFailedAttempts(authenticatingUser);
            }
            resetContextRetryCount(context);
            resetContextResendCount(context);
            context.removeProperty(getName() + ".otpAlreadySentInFlow");
            publishPostOTPValidatedEvent(otpInContext, authenticatedUserFromContext, true, false, request, context);
            return;
        }
        /*
         * Handle when the OTP is unsuccessful. At this point user account is not locked. Locked scenario is
         * handled from the above steps.
         */
        if (!isInitialFederationAttempt) {
            // A mapped user is not available for isInitialFederationAttempt true scenario.
            handleOtpVerificationFail(authenticatingUser);
        }

        handleInvalidOTPLoginAttempt(context, applicationTenantDomain);

        if (otpInContext != null && otpInContext.isExpired()) {
            publishPostOTPValidatedEvent(otpInContext, authenticatedUserFromContext, false,
                    true, request, context);
            throw handleAuthErrorScenario(ERROR_CODE_OTP_EXPIRED,
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
        } else {
            publishPostOTPValidatedEvent(otpInContext, authenticatedUserFromContext, false,
                    false, request, context);
            throw handleAuthErrorScenario(ERROR_CODE_OTP_INVALID,
                    AuthenticatorUtils.maskIfRequired(authenticatedUserFromContext.getUserName()));
        }
    }

    /**
     * Check whether the current scenario is an OTP resend attempt and the resend limit has been
     * exceeded for the context.
     *
     * @param scenario The current authentication scenario.
     * @param isUserBasedOTPResendBlockingEnabled Whether user based OTP resend blocking is enabled.
     * @param context Authentication context.
     * @return true if it's an OTP resend attempt and the resend limit has been exceeded, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while checking the resend limit.
     */
    private boolean isOTPResendLimitExceededScenario(AuthenticatorConstants.AuthenticationScenarios scenario,
                                                  boolean isUserBasedOTPResendBlockingEnabled,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        return scenario == RESEND_OTP
                && (!isUserBasedOTPResendBlockingEnabled || isContextBasedOTPResendBlockingEnabled(context))
                && isOTPResendLimitExceeded(context, context.getTenantDomain());


    }

    /**
     *  Check whether the OTP resend count has exceeded the allowed limit for the context.
     *
     * @param context Authentication context.
     * @param applicationTenantDomain Application tenant domain.
     * @return true if the resend count has exceeded, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while checking the resend count.
     */
    private boolean isOTPResendLimitExceeded(AuthenticationContext context, String applicationTenantDomain)
            throws AuthenticationFailedException {

        int allowedResendAttemptsCount = getMaximumResendAttempts(applicationTenantDomain, context);
        int currentResendAttempt = getCurrentResendAttempt(context);
        return currentResendAttempt >= allowedResendAttemptsCount;
    }

    /**
     * Handle the OTP login attempt count and block the authentication flow
     * if the count has exceeded the allowed limit for the context.
     *
     * @param context Authentication context.
     * @param applicationTenantDomain Application tenant domain.
     * @throws AuthenticationFailedException If an error occurs while handling the retry blocking scenario.
     */
    private void handleInvalidOTPLoginAttempt(AuthenticationContext context, String applicationTenantDomain)
            throws AuthenticationFailedException {

        if (isContextBasedRetryBlockingEnabled(context)) {
            // Update Context based retry counter only if context based retry blocking is enabled.
            updateContextOTPRetryCount(context);
            int maxRetryAttempts = getMaximumRetryAttempts(applicationTenantDomain, context);
            int currentRetryAttempts = getCurrentRetryAttempt(context);
            if (currentRetryAttempts >= maxRetryAttempts) {
                handleOTPRetryCountExceededScenario(context);
            }
        }
    }

    /**
     * Check whether the user exists in the user store.
     *
     * @param authenticatedUser Authenticated user.
     * @param context          Authentication context.
     * @return True if the user exists, false otherwise.
     *
     * @throws AuthenticationFailedException In case of an error while checking user existence.
     */
    private boolean isUserExists(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (authenticatedUser.isFederatedUser()) {
            UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
            try {
                return userStoreManager.isExistingUser(
                        MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername()));
            } catch (UserStoreException e) {
                throw handleAuthErrorScenario(ERROR_CODE_ERROR_CHECKING_USER_EXISTENCE, e, context,
                        org.wso2.carbon.identity.auth.otp.core.util.AuthenticatorUtils.maskIfRequired(
                                authenticatedUser.getUserName()));
            }
        }
        return true;
    }

    /**
     * Handle OTP for account locked users.
     *
     * @param authenticatedUser Authenticated user provisioned in the server.
     * @param response          HttpServletResponse.
     * @param context           AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleOTPForLockedUser(AuthenticatedUser authenticatedUser, HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        // By default, we are showing the authentication failure reason here.
        long unlockTime = getUnlockTimeInMilliSeconds(authenticatedUser);
        long timeToUnlock = unlockTime - System.currentTimeMillis();
        if (timeToUnlock > 0) {
            queryParams += UNLOCK_QUERY_PARAM + Math.round((double) timeToUnlock / 1000 / 60);
        }
        redirectToErrorPage(request, response, context, queryParams, ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS);
    }

    /**
     * Get user account unlock time in milliseconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milliseconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        String accountLockedTime = getUserClaimValueFromUserStore(ACCOUNT_UNLOCK_TIME_CLAIM, authenticatedUser,
                ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME);
        if (StringUtils.isBlank(accountLockedTime)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No value configured for claim: %s for user: %s", ACCOUNT_UNLOCK_TIME_CLAIM,
                        username));
            }
            return 0;
        }
        return Long.parseLong(accountLockedTime);
    }

    /**
     * Get user claim value.
     *
     * @param claimUri          Claim uri.
     * @param authenticatedUser AuthenticatedUser.
     * @param error             Error associated with the claim retrieval.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    protected String getUserClaimValueFromUserStore(String claimUri, AuthenticatedUser authenticatedUser,
                                                    AuthenticatorConstants.ErrorMessages error)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUri}, null);
            return claimValues.get(claimUri);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(error, e, AuthenticatorUtils.maskIfRequired(authenticatedUser.getUserName()));
        }
    }

    /**
     * Get user claim value.
     *
     * @param userClaims        Map of claim uri and values.
     * @param authenticatedUser AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    protected void setUserClaimValueFromUserStore(Map<String, String> userClaims, AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            userStoreManager.setUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                    authenticatedUser.toFullQualifiedUsername()), userClaims, null);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_UPDATING_USER_CLAIMS, e,
                    AuthenticatorUtils.maskIfRequired(authenticatedUser.getUserName()));
        }
    }

    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, username);
            }
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, e,
                    AuthenticatorUtils.maskIfRequired(username));
        }
    }

    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws AuthenticationFailedException If an error occurred while getting the UserRealm.
     */
    private UserRealm getTenantUserRealm(String tenantDomain) throws AuthenticationFailedException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (AuthenticatorDataHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_REALM, e, tenantDomain);
        }
        if (userRealm == null) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_REALM, tenantDomain);
        }
        return userRealm;
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }
        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw handleAuthErrorScenario(ERROR_CODE_NO_FEDERATED_USER);
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername,
                                                        String tenantDomain, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            return authenticatedUserInContext;
        }
        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }
        /*
         * At this point, the authenticating user is in our system but has a different mapped username compared to the
         * identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
         * with the mapped local username to identify the user.
         */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    /**
     * Get the authenticated user by iterating though auth steps.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser.
     * @throws AuthenticationFailedException If no authenticated user was found.
     */
    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser user = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && user != null) {
                AuthenticatedUser authenticatedUser = new AuthenticatedUser(user);
                if (StringUtils.isBlank(authenticatedUser.toFullQualifiedUsername())) {
                    LOG.debug("Username can not be empty");
                    throw handleAuthErrorScenario(ERROR_CODE_EMPTY_USERNAME);
                }
                return authenticatedUser;
            }
        }

        StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
        if (currentStepConfig.isSubjectAttributeStep()) {
            return null;
        }

        // If authenticated user cannot be found from the previous steps.
        throw handleAuthErrorScenario(ERROR_CODE_NO_USER_FOUND);
    }

    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error) {

        return handleAuthErrorScenario(error, (Object) null);
    }

    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                    Object... data) {

        return handleAuthErrorScenario(error, null, data);
    }

    /**
     * Handle the scenario by returning AuthenticationFailedException which has the details of the error scenario.
     *
     * @param error     {@link AuthenticatorConstants.ErrorMessages} error message.
     * @param throwable Throwable.
     * @param data      Additional data related to the scenario.
     * @return AuthenticationFailedException.
     */
    protected AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                    Throwable throwable, Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        String errorCode = getAuthenticatorErrorPrefix() + "-" + error.getCode();
        if (throwable == null) {
            return new AuthenticationFailedException(errorCode, message);
        }
        return new AuthenticationFailedException(errorCode, message, throwable);
    }

    /**
     * To redirect flow to error page with specific condition.
     *
     * @param response    The httpServletResponse.
     * @param context     The AuthenticationContext.
     * @param queryParams The query params.
     * @param retryParam  The retry param.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void redirectToErrorPage(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context, String queryParams, String retryParam)
            throws AuthenticationFailedException {

        try {
            String multiOptionURIQueryString = AuthenticatorUtils.getMultiOptionURIQueryString(request);
            String userName;
            userName = context.getLastAuthenticatedUser() != null
                    ? context.getLastAuthenticatedUser().getUserName()
                    : StringUtils.isNotBlank((String) context.getProperty(INVALID_USERNAME))
                    ? (String) context.getProperty(INVALID_USERNAME)
                    : UNKNOWN_USER;
            String queryString = queryParams + AUTHENTICATORS_QUERY_PARAM + getName() +
                    USERNAME_PARAM + userName + retryParam
                    + multiOptionURIQueryString;
            String errorPage = getErrorPageURL(context);
            String url = FrameworkUtils.appendQueryParamsStringToUrl(errorPage, queryString);
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE, e, (Object) null);
        }
    }

    /**
     * Handle OTP resend attempts count exceeded scenarios by terminating the flow or redirecting to error page based on the configuration.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @param user    Authenticated user.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleOTPResendCountExceededScenario(HttpServletRequest request, HttpServletResponse response,
                                                      AuthenticationContext context, AuthenticatedUser user)
            throws AuthenticationFailedException {

        handleOTPResendCountExceededScenario(request, response, context,
                user, isTerminateOnResendLimitExceeded(context));
    }

    /**
     * Handle OTP retry attempts count exceeded scenario by terminating the flow or redirecting to error page based on the configuration.
     *
     * @param context  AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleOTPRetryCountExceededScenario(AuthenticationContext context)
            throws AuthenticationFailedException {

        context.setProperty(SKIP_RETRY_FROM_AUTHENTICATOR, true);
        context.setProperty(FrameworkConstants.AUTH_ERROR_CODE,
                FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED);
    }

    /**
     * Handle OTP resend attempts count exceeded scenarios.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @param user    Authenticated user.
     * @param terminateFlow Whether to terminate the flow by throwing an exception or to redirect to error page.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleOTPResendCountExceededScenario(HttpServletRequest request, HttpServletResponse response,
                                                      AuthenticationContext context, AuthenticatedUser user,
                                                      boolean terminateFlow)
            throws AuthenticationFailedException {

        if (terminateFlow) {
            context.setRetrying(false);
            context.setProperty(FrameworkConstants.AUTH_ERROR_CODE,
                    FrameworkConstants.ERROR_STATUS_ALLOWED_RESEND_LIMIT_EXCEEDED);
            if (user != null) {
                throw handleAuthErrorScenario(ERROR_CODE_RESEND_LIMIT_EXCEEDED,
                        AuthenticatorUtils.maskIfRequired(user.getUserName()));
            }
            throw handleAuthErrorScenario(ERROR_CODE_RESEND_LIMIT_EXCEEDED, UNKNOWN_USER);
        }
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        redirectToErrorPage(request, response, context, queryParams, ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS);
    }

    protected AuthenticatorConstants.AuthenticationScenarios resolveScenario(HttpServletRequest request,
                                                                             AuthenticationContext context) {

        if (context.isLogoutRequest()) {
            return LOGOUT;
        } else if (!context.isRetrying() && StringUtils.isBlank(request.getParameter(CODE)) &&
                StringUtils.isBlank(request.getParameter(RESEND))) {
            return INITIAL_OTP;
        } else if (context.isRetrying() && StringUtils.isNotBlank(request.getParameter(RESEND)) &&
                Boolean.parseBoolean(request.getParameter(RESEND))) {
            return RESEND_OTP;
        }
        return SUBMIT_OTP;
    }

    /**
     * To redirect the flow to otp login page to enter an OTP.
     *
     * @param response      HttpServletResponse.
     * @param request       HttpServletRequest.
     * @param context       AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred while redirecting to otp login page.
     */
    protected void redirectToOTPLoginPage(AuthenticatedUser authenticatedUser, String tenantDomain,
                                          boolean isInitialFederationAttempt, HttpServletResponse response,
                                          HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = authenticatedUser.getUserName();
        StringBuilder queryParamsBuilder = new StringBuilder();
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        queryParamsBuilder.append(queryParams)
                .append(AUTHENTICATORS_QUERY_PARAM).append(getName())
                .append(USERNAME_PARAM).append(username)
                .append(multiOptionURI);

        if (!isOTPAsFirstFactor(context)) {
            String maskedUserClaimValue = getMaskedUserClaimValue(authenticatedUser, tenantDomain,
                    isInitialFederationAttempt, context);
            if (!StringUtils.isBlank(maskedUserClaimValue)) {
                String screenValueQueryParam = SCREEN_VALUE_QUERY_PARAM
                        + getMaskedUserClaimValue(authenticatedUser, tenantDomain,
                        isInitialFederationAttempt, context);
                queryParamsBuilder.append(screenValueQueryParam);
            }
        }
        boolean retryParamsAdded = false;
        if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(RESEND))) {
            if (isShowAuthFailureReason()) {
                String remainingNumberOfOtpAttemptsQueryParam = getRemainingNumberOfOtpAttemptsQueryParam();
                if (StringUtils.isNotBlank(remainingNumberOfOtpAttemptsQueryParam)) {
                    int remainingNumberOfOtpAttempts =
                            getRemainingNumberOfOtpAttempts(authenticatedUser, tenantDomain, context);
                    queryParamsBuilder.append(getRemainingNumberOfOtpAttemptsQueryParam())
                            .append(remainingNumberOfOtpAttempts);
                }
            }
            queryParamsBuilder.append(RETRY_QUERY_PARAMS);
            retryParamsAdded = true;
        }
        if (isOTPAsFirstFactor(context)) {
            String captchaParams = getCaptchaParams(request, context, tenantDomain, authenticatedUser);
            queryParamsBuilder.append(captchaParams);
        }
        String additionalErrorCode = getOTPPageRedirectErrorCode(context);
        if (StringUtils.isNotBlank(additionalErrorCode)) {
            if (!retryParamsAdded) {
                queryParamsBuilder.append(RETRY_QUERY_PARAMS);
            }
            queryParamsBuilder.append(ERROR_CODE_QUERY_PARAM).append(additionalErrorCode);
        }
        try {
            String otpLoginPage = getOTPLoginPageURL(context);
            String url = FrameworkUtils.appendQueryParamsStringToUrl(otpLoginPage, queryParamsBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE, e, (Object) null);
        }
    }

    /**
     * Get remaining number of OTP attempts to show in the login page when the user has entered an invalid OTP and
     * retrying.This is calculated based on the remaining number of attempts for account lock and context based retry
     * blocking if enabled.
     *
     * @param authenticatedUser Authenticated user.
     * @param tenantDomain Tenant domain.
     * @param context Authentication context.
     * @return Query parameter to show the remaining number of OTP attempts.
     */
    private int getRemainingNumberOfOtpAttempts(AuthenticatedUser authenticatedUser,
                                                String tenantDomain,
                                                AuthenticationContext context)
            throws AuthenticationFailedException {

        if (isContextBasedRetryBlockingEnabled(context)) {
            return Math.min(getRemainingNumberOfOtpAttemptsForAccountLock(authenticatedUser, tenantDomain),
                    getRemainingNumberOfContextBasedRetryAttempts(context));
        } else {
            return getRemainingNumberOfOtpAttemptsForAccountLock(authenticatedUser, tenantDomain);
        }
    }

    /**
     * Get the remaining number of context based retry attempts.
     *
     * @param context Authentication context.
     * @return Remaining number of context based retry attempts.
     * @throws AuthenticationFailedException If an error occurred while getting the remaining number of
     *                                       context based retry attempts.
     */
    private int getRemainingNumberOfContextBasedRetryAttempts(AuthenticationContext context)
            throws AuthenticationFailedException {

        int maxRetryAttempts = getMaximumRetryAttempts(context.getTenantDomain(), context);
        int currentRetryAttempts = getCurrentRetryAttempt(context);
        int remainingRetryAttempts = maxRetryAttempts - currentRetryAttempts;
        // If the remaining retry attempts is less than 0, then return 0.
        return Math.max(remainingRetryAttempts, 0);
    }

    /**
     * Get the remaining number of OTP attempts for account lock.
     *
     * @param authenticatedUser Authenticated user.
     * @param tenantDomain      Tenant domain.
     * @return Remaining number of OTP attempts for account lock.
     * @throws AuthenticationFailedException If an error occurred while getting the remaining number of OTP attempts.
     */
    private int getRemainingNumberOfOtpAttemptsForAccountLock(AuthenticatedUser authenticatedUser, String tenantDomain)
            throws AuthenticationFailedException {

        try {
            UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
            String failedAttemptsClaim = getOTPFailedAttemptsClaimUri();
            if (userStoreManager == null) {
                throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER);
            }
            String fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(MultitenantUtils
                            .getTenantAwareUsername(fullQualifiedUsername),
                    new String[]{failedAttemptsClaim}, null);
            String failedOtpAttempts = claimValues.get(failedAttemptsClaim);
            int maxFailedAttemptsOnAccountLock = Arrays.stream(AuthenticatorUtils
                            .getAccountLockConnectorConfigs(tenantDomain))
                    .filter(config -> FAILED_LOGIN_ATTEMPTS_PROPERTY
                            .equals(config.getName())).findFirst()
                    .map(config -> Integer.parseInt(config.getValue()))
                    .orElseThrow(() -> new AuthenticationFailedException("No configuration found for " +
                            FAILED_LOGIN_ATTEMPTS_PROPERTY));
            int parsedFailedAttempts = (failedOtpAttempts != null) ? Integer.parseInt(failedOtpAttempts) : 0;
            return maxFailedAttemptsOnAccountLock - parsedFailedAttempts;
        } catch (UserStoreException e) {
            String errorMessage =
                    String.format("Failed to get remaining attempts count for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Get the JIT provisioning user store domain of the authenticated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Tenant domain.
     * @return JIT provisioning user store domain.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Setting user store: %s as the provisioning user store for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = AuthenticatorDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw handleAuthErrorScenario(ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }
    }

    private InvalidCredentialsException handleInvalidCredentialsScenario(AuthenticatorConstants.ErrorMessages error,
                                                                         String... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, (Object) data);
        }
        LOG.debug(message);
        return new InvalidCredentialsException(error.getCode(), message);
    }

    /**
     * Check whether the given OTP value is valid.
     *
     * @param userToken    User given otp.
     * @param user         AuthenticatedUser.
     * @param context      AuthenticationContext.
     * @return True if the OTP is valid.
     * @throws AuthenticationFailedException If error occurred while validating the OTP.
     */
    private boolean isSuccessfulAuthAttempt(String userToken, AuthenticatedUser user, AuthenticationContext context)
            throws AuthenticationFailedException {

        OTP otpInfoInContext = (OTP) context.getProperty(OTP);
        if (StringUtils.isBlank(userToken)) {
            throw handleAuthErrorScenario(ERROR_CODE_EMPTY_OTP_CODE,
                    AuthenticatorUtils.maskIfRequired(user.getUserName()));
        }
        if (otpInfoInContext == null || StringUtils.isBlank(otpInfoInContext.getValue())) {
            return false;
        }
        boolean isExpired = otpInfoInContext.isExpired();
        if (userToken.equals(otpInfoInContext.getValue())) {
            if (isExpired) {
                return false;
            } else {
                context.setProperty(OTP, null);
                context.setSubject(user);
                return true;
            }
        }  else {
            // This is the OTP mismatched scenario.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Invalid OTP given by the user: " + user.getUserName());
            }
            return false;
        }
    }

    /**
     * Generate the OTP according to the configuration parameters.
     *
     * @param tenantDomain Tenant domain.
     * @return Generated OTP.
     * @throws AuthenticationFailedException If an error occurred.
     */
    protected OTP generateOTP(String tenantDomain) throws AuthenticationFailedException {

        String charSet = getOTPCharset(tenantDomain);
        int otpLength = getOTPLength(tenantDomain);

        char[] chars = charSet.toCharArray();
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            stringBuilder.append(chars[secureRandom.nextInt(chars.length)]);
        }
        String token = stringBuilder.toString();
        return new OTP(token, System.currentTimeMillis(), getOtpValidityPeriodInMillis(tenantDomain));
    }

    /**
     * Get the number of maximum attempts the user is allowed resend the OTP.
     *
     * @param tenantDomain  Tenant Domain.
     * @return The maximum number of resend attempts.
     * @throws AuthenticationFailedException If an error occurs when retrieving config.
     */
    protected int getMaximumResendAttempts(String tenantDomain) throws AuthenticationFailedException {

        return DEFAULT_OTP_RESEND_ATTEMPTS;
    }

    /**
     * Get the number of maximum attempts the user is allowed resend the OTP.
     *
     * @param tenantDomain  Tenant Domain.
     * @param context Authentication Context.
     * @return The maximum number of resend attempts.
     * @throws AuthenticationFailedException If an error occurs when retrieving config.
     */
    protected int getMaximumResendAttempts(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (isContextBasedOTPResendBlockingEnabled(context)) {
            OptionalInt maxResendAttemptsFromContext = AuthenticatorUtils.getIntRuntimeParamByName(
                    getRuntimeParams(context), MAXIMUM_RESEND_LIMIT);
            return maxResendAttemptsFromContext.isPresent() ?
                    maxResendAttemptsFromContext.getAsInt() : getMaximumResendAttempts(tenantDomain);
        }

        return getMaximumResendAttempts(tenantDomain);
    }

    /**
     * Get the number of maximum attempts the user is allowed to retry OTP submission.
     *
     * @param tenantDomain  Tenant Domain.
     * @param context Authentication Context.
     * @return The maximum number of retry attempts.
     * @throws AuthenticationFailedException If an error occurs when retrieving config.
     */
    protected int getMaximumRetryAttempts(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (isContextBasedRetryBlockingEnabled(context)) {
            OptionalInt maxRetryAttemptsFromContext = AuthenticatorUtils.getIntRuntimeParamByName(
                    getRuntimeParams(context), MAXIMUM_ALLOWED_FAILURE_LIMIT);
            return maxRetryAttemptsFromContext.isPresent() ? maxRetryAttemptsFromContext.getAsInt() :
                    Integer.MAX_VALUE;
        }
        return Integer.MAX_VALUE;
    }

    /**
     * Initializes or increments the OTP resend attempt counter for the current authentication
     * context. This counter is maintained only in context and is not persisted as a user attribute.
     * The updated count is evaluated when enforcing context-level resend limits.
     *
     * @param context Authentication context of the ongoing authentication flow.
     */
    protected void updateContextOTPResendCount(AuthenticationContext context) {

        incrementContextCounter(context, getResendAttemptsPropertyKey());
    }

    /**
     * Initializes or increments the OTP submission attempt counter for the current authentication
     * context. This counter is maintained only in context and is not persisted as a user attribute.
     * The updated count is evaluated when enforcing context-level retry limits.
     *
     * @param context Authentication context of the ongoing authentication flow.
     */
    protected void updateContextOTPRetryCount(AuthenticationContext context) {

        incrementContextCounter(context, getRetryAttemptsPropertyKey());
    }

    /**
     * Initializes a context counter to 1 if not already set, or increments it by 1.
     *
     * @param context Authentication context of the ongoing authentication flow.
     * @param key     The context property key of the counter.
     */
    private void incrementContextCounter(AuthenticationContext context, String key) {

        if (context.getProperty(key) == null ||
                StringUtils.isBlank(context.getProperty(key).toString())) {
            context.setProperty(key, 1);
        } else {
            context.setProperty(key, (int) context.getProperty(key) + 1);
        }
    }

    /**
     * Reset the number of times the user attempted to submit OTP.
     *
     * @param context   Authentication Context.
     */
    protected void resetContextRetryCount(AuthenticationContext context) {

        context.setProperty(getRetryAttemptsPropertyKey(), 0);
    }

    /**
     * Reset the number of times the OTP was resent to the user.
     *
     * @param context   Authentication Context.
     */
    protected void resetContextResendCount(AuthenticationContext context) {

        context.setProperty(getResendAttemptsPropertyKey(), 0);
    }

    /**
     * Get the current count of OTP retry attempts from the context.
     *
     * @param context   Authentication Context.
     * @return The number of times the user attempted to submit OTP in the current authentication flow.
     */
    protected int getCurrentRetryAttempt(AuthenticationContext context) {

        return getContextCounter(context, getRetryAttemptsPropertyKey());
    }

    /**
     * Get the current count of OTP resend attempts from the context.
     *
     * @param context   Authentication Context.
     * @return The number of times the user attempted to resend OTP in the current authentication flow.
     */
    protected int getCurrentResendAttempt(AuthenticationContext context) {

        return getContextCounter(context, getResendAttemptsPropertyKey());
    }

    /**
     * Get the current value of a context counter, returning 0 if not set.
     *
     * @param context Authentication context of the ongoing authentication flow.
     * @param key     The context property key of the counter.
     * @return The current counter value, or 0 if absent or blank.
     */
    private int getContextCounter(AuthenticationContext context, String key) {

        if (context.getProperty(key) == null ||
                StringUtils.isBlank(context.getProperty(key).toString())) {
            return 0;
        }
        return Integer.parseInt(context.getProperty(key).toString());
    }

    /**
     * Get the context property key used to store the OTP resend attempt count.
     * Subclasses may override this to use a different key.
     *
     * @return The context property key for OTP resend attempts.
     */
    protected String getResendAttemptsPropertyKey() {

        return DEFAULT_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME;
    }

    /**
     * Get the context property key used to store the OTP retry attempt count.
     * Subclasses may override this to use a different key.
     *
     * @return The context property key for OTP retry attempts.
     */
    protected String getRetryAttemptsPropertyKey() {

        return DEFAULT_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME;
    }

    /**
     * This method defines the character set used for the OTP generation.
     *
     * @param tenantDomain  Tenant Domain.
     * @return Character set.
     * @throws AuthenticationFailedException If an error occurs when retrieving config.
     */
    private String getOTPCharset(String tenantDomain) throws AuthenticationFailedException {

        boolean useOnlyNumericChars = useOnlyNumericChars(tenantDomain);
        if (useOnlyNumericChars) {
            return OTP_NUMERIC_CHAR_SET;
        }
        return OTP_ALPHA_NUMERIC_CHAR_SET;
    }

    /**
     * This method defines the length of the OTP to be generated.
     *
     * @param tenantDomain  Tenant Domain.
     * @return length of the OTP.
     * @throws AuthenticationFailedException If an error occurs when retrieving the value.
     */
    protected int getOTPLength(String tenantDomain) throws AuthenticationFailedException {

        return DEFAULT_OTP_LENGTH;
    }

    /**
     * This method defines whether the OTP should consist of only numeric characters.
     * Alternative is to use alphanumeric characters.
     *
     * @param tenantDomain  Tenant Domain.
     * @return if the OTP should consist of only numeric characters.
     * @throws AuthenticationFailedException If an error occurs when retrieving the value.
     */
    protected boolean useOnlyNumericChars(String tenantDomain) throws AuthenticationFailedException {

        return true;
    }

    /**
     * This method defines validity period of the OTP set for the tenant domain.
     *
     * @param tenantDomain  Tenant Domain.
     * @return validity period in milliseconds.
     */
    protected long getOtpValidityPeriodInMillis(String tenantDomain) throws AuthenticationFailedException {

        return DEFAULT_OTP_VALIDITY_IN_MILLIS;
    }

    /**
     * This method defines URI of the claim used to determine if the user account should be locked/unlocked
     * after an authentication attempt completes.
     *
     * @return the URI of the claim that counts consecutive invalid login attempts.
     */
    protected String getOTPFailedAttemptsClaimUri() throws AuthenticationFailedException {

        return FAILED_LOGIN_ATTEMPTS_CLAIM_URI;
    }

    /**
     * Execute account lock flow for OTP verification failures. By default, the OTP
     * authenticator will support account lock on failed attempts if the account locking is enabled for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    protected void handleOtpVerificationFail(AuthenticatedUser user) throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, getName());
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, getOTPFailedAttemptsClaimUri());
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, false);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    /**
     * Trigger event.
     *
     * @param eventName      Event name.
     * @param user           Authenticated user.
     * @param eventProperties Meta details.
     * @throws AuthenticationFailedException If an error occurred while triggering the event.
     */
    protected void triggerEvent(String eventName, AuthenticatedUser user,
                                Map<String, Object> eventProperties) throws AuthenticationFailedException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        if (eventProperties != null) {
            for (Map.Entry<String, Object> metaProperty : eventProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AuthenticatorDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            if (ERROR_CODE_MISSING_SMS_SENDER.equals(e.getErrorCode())) {
                throw handleAuthErrorScenario(ERROR_CODE_NO_MOBILE_NUMBER_FOUND, e, user.getLoggableUserId());
            }
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_TRIGGERING_EVENT, e, eventName,
                    AuthenticatorUtils.maskIfRequired(user.getUserName()));
        }
    }

    /**
     * This method is used to redirect the user to the username entering page (IDF: Identifier first).
     *
     * @param request  Request.
     * @param response Response.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException If an error occurred while setting redirect url.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    private void redirectUserToIDF(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationContext context) throws AuthenticationFailedException {

        StringBuilder redirectUrl = new StringBuilder();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        redirectUrl.append(loginPage);
        redirectUrl.append("?");

        String queryParams = context.getContextIdIncludedQueryParams();
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryString(request);
        try {
            LOG.debug("Redirecting to identifier first flow since no authenticated user was found");
            if (queryParams != null) {
                redirectUrl.append(queryParams);
                redirectUrl.append("&");
            }
            redirectUrl.append(AUTHENTICATORS);
            redirectUrl.append(IDF_HANDLER_NAME);
            redirectUrl.append(":");
            redirectUrl.append(LOCAL_AUTHENTICATOR);
            redirectUrl.append(multiOptionURI);
            response.sendRedirect(redirectUrl.toString());
        } catch (IOException e) {
            throw handleAuthErrorScenario(ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE);
        }
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param request The httpServletRequest.
     * @param context The authentication context.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromRequest(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(USERNAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw handleAuthErrorScenario(ERROR_CODE_EMPTY_USERNAME);
        }
        String username = FrameworkUtils.preprocessUsernameWithContextTenantDomain(identifierFromRequest, context);
        AuthenticatedUser user = new AuthenticatedUser();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setAuthenticatedSubjectIdentifier(tenantAwareUsername);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * This method is used to resolve an authenticated user from the user stores.
     *
     * @param authenticatedUser The authenticated user.
     * @return Authenticated user retrieved from the user store.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromUserStore(AuthenticatedUser authenticatedUser,
                                                       AuthenticationContext context)
            throws AuthenticationFailedException {

        User user = getUser(authenticatedUser, context);
        if (user == null) {
            return null;
        }
        authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUsername());
        return authenticatedUser;
    }

    /**
     * This method is used to set the resolved user in context.
     *
     * @param context           The authentication context.
     * @param authenticatedUser The authenticated user.
     */
    private void setResolvedUserInContext(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        if (authenticatedUser != null) {
            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
            if (currentStepConfig.isSubjectAttributeStep()) {
                context.setSubject(authenticatedUser);
                currentStepConfig.setAuthenticatedUser(authenticatedUser);
                currentStepConfig.setAuthenticatedIdP(LOCAL_AUTHENTICATOR);
            }
        }
    }

    /**
     * Append the recaptcha related params if recaptcha is enabled for OTP authenticator.
     *
     * @param request           HTTP servlet request.
     * @param context           Authentication context.
     * @param tenantDomain      Tenant domain.
     * @param authenticatedUser Authenticated User.
     * @return String with the appended recaptcha params.
     */
    protected String getCaptchaParams(HttpServletRequest request, AuthenticationContext context, String tenantDomain,
                                      AuthenticatedUser authenticatedUser) {

        if (!isOTPAsFirstFactor(context)) {
            return StringUtils.EMPTY;
        }

        SSOLoginReCaptchaConfig connector = new SSOLoginReCaptchaConfig();
        String captchaEnabledConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE;
        String captchaAlwaysEnabledConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE_ALWAYS;
        String maxFailedAttemptCaptchaConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.MAX_ATTEMPTS;

        String captchaParams = StringUtils.EMPTY;
        Property[] connectorConfigs;

        if (CaptchaUtil.isReCaptchaEnabled()) {
            boolean forcefullyEnabledRecaptchaForAllTenants = CaptchaUtil.isReCaptchaForcefullyEnabledForAllTenants();
            if (forcefullyEnabledRecaptchaForAllTenants) {
                captchaParams = RECAPTCHA_PARAM + "true";
            } else {
                try {
                    connectorConfigs = AuthenticatorDataHolder.getIdentityGovernanceService()
                            .getConfiguration(new String[]{captchaAlwaysEnabledConfigName, captchaEnabledConfigName},
                                    tenantDomain);
                    for (Property connectorConfig : connectorConfigs) {
                        if (captchaAlwaysEnabledConfigName.equals(connectorConfig.getName())
                                && Boolean.parseBoolean(connectorConfig.getValue())) {
                            captchaParams = RECAPTCHA_PARAM + "true";
                            break;
                        } else if (captchaEnabledConfigName.equals(connectorConfig.getName())) {
                            if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                                continue;
                            }
                            if (Boolean.parseBoolean(
                                    String.valueOf(context.getProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER)))) {
                                continue;
                            }
                            Property[] maxFailedConfig = AuthenticatorDataHolder.getIdentityGovernanceService()
                                    .getConfiguration(new String[]{maxFailedAttemptCaptchaConfigName}, tenantDomain);
                            Property maxFailedProperty = maxFailedConfig[0];
                            int maxFailedAttempts;
                            if (NumberUtils.isNumber(maxFailedProperty.getValue())) {
                                maxFailedAttempts = Integer.parseInt(maxFailedProperty.getValue());
                            } else {
                                maxFailedAttempts = 3;
                            }

                            UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
                            Map<String, String> claimValues;
                            String failedAttemptsClaim = getOTPFailedAttemptsClaimUri();
                            if (userStoreManager == null) {
                                throw handleAuthErrorScenario(ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER);
                            }
                            String fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
                            claimValues = userStoreManager.getUserClaimValues(MultitenantUtils
                                            .getTenantAwareUsername(fullQualifiedUsername),
                                    new String[]{failedAttemptsClaim}, null);

                            int currentAttempts = 0;
                            if (NumberUtils.isNumber(claimValues.get(failedAttemptsClaim))) {
                                currentAttempts = Integer.parseInt(claimValues.get(failedAttemptsClaim));
                            }
                            if (maxFailedAttempts > currentAttempts) {
                                continue;
                            }
                            captchaParams = RECAPTCHA_PARAM + "true";
                        }
                    }

                } catch (IdentityGovernanceException | UserStoreException | AuthenticationFailedException e) {
                    LOG.error("Error occurred while verifying the captcha configs. Proceeding the authentication " +
                            "request without enabling recaptcha.", e);
                }
            }
        }
        return captchaParams;
    }

    /**
     * Reset OTP Failed Attempts count upon successful completion of the OTP verification.
     *
     * @param user AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    protected void resetOtpFailedAttempts(AuthenticatedUser user) throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, getName());
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, getOTPFailedAttemptsClaimUri());
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, true);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    /**
     * Check if the current authentication attempt is performed by a user who is not in the system.
     *
     * @param context               Authentication Context.
     * @param authenticatedUser     User who is attempting the authentication.
     * @return True if the authentication attempt is done by an invalid user.
     */
    private boolean isLoginAttemptByInvalidUser(AuthenticationContext context,
                                                AuthenticatedUser authenticatedUser) {

        return authenticatedUser == null
                && Boolean.parseBoolean(String.valueOf(context.getProperty(IS_LOGIN_ATTEMPT_BY_INVALID_USER)));
    }

    /**
     * Check if the user is redirected from the identifier first UI.
     *
     * @param request   HttpServletRequest.
     * @return True if the user is redirected from the identifier first UI.
     */
    private boolean isUserRedirectedFromIDF(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(USERNAME));
    }

    /**
     * Check if the first factor support for the authenticator is enabled through config.
     *
     * @return True if enabled.
     */
    protected boolean isAuthenticatorEnabledForFirstFactor() {

        return true;
    }

    /**
     * Check if the current OTP authenticator is the primary factor of authentication.
     *
     * @param context   Authentication Context.
     * @return True if the current OTP authenticator is the primary factor of authentication.
     */
    protected boolean isOTPAsFirstFactor(AuthenticationContext context) {

        return (context.getCurrentStep() == 1 || AuthenticatorUtils.isPreviousIdPAuthenticationFlowHandler(context));
    }

    protected abstract String getAuthenticatorErrorPrefix();

    protected abstract void sendOtp(AuthenticatedUser authenticatedUser, OTP otp, boolean isInitialFederationAttempt,
                                    HttpServletRequest request, HttpServletResponse response,
                                    AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract String getMaskedUserClaimValue(AuthenticatedUser authenticatedUser, String tenantDomain,
                                                      boolean isInitialFederationAttempt, AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract void publishPostOTPValidatedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                         boolean isAuthenticationPassed, boolean isExpired,
                                                         HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract void publishPostOTPGeneratedEvent(OTP otpInfo, AuthenticatedUser authenticatedUser,
                                                         HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException;

    protected abstract String getErrorPageURL(AuthenticationContext context) throws AuthenticationFailedException;

    protected abstract String getOTPLoginPageURL(AuthenticationContext context) throws AuthenticationFailedException;

    protected String getRemainingNumberOfOtpAttemptsQueryParam() {

        return null;
    }

    /**
     * Returns an error code to be appended to the OTP login page redirect URL.
     * If null is returned, no error code is added. When a non-null value is returned and the retry
     * params have not yet been added to the URL, they will be added automatically.
     *
     * @param context Authentication context.
     * @return Error code string, or null to skip.
     */
    protected String getOTPPageRedirectErrorCode(AuthenticationContext context) throws AuthenticationFailedException {

        return null;
    }

    protected  boolean isShowAuthFailureReason() {

        return false;
    }
}
