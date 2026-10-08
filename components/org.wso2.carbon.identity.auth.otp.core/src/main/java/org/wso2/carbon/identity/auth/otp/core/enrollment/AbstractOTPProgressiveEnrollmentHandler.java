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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.auth.otp.core.util.AuthenticatorUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.ATTEMPTS_EXCEEDED_MESSAGE_SUFFIX;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.AUTH_FAILURE_QUERY_PARAMS;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.AWAITING_VALUE;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.ENROLLMENT_ATTEMPTS;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.ENROLLMENT_ERROR;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.ENROLLMENT_FAILED_MESSAGE_SUFFIX;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.INVALID_VALUE_MESSAGE_SUFFIX;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.OTP_SENT_TO_VALUE;
import static org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants.PENDING_VALUE;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * Lets a user without a value for an OTP channel, such as a mobile number, enroll one during authentication. The value
 * is saved as verified only after the OTP sent to it is verified. Handlers are stateless; the enrollment state is kept
 * in the authentication context.
 */
public abstract class AbstractOTPProgressiveEnrollmentHandler {

    private static final Log LOG = LogFactory.getLog(AbstractOTPProgressiveEnrollmentHandler.class);

    private final String authenticatorName;
    private final String errorCodePrefix;
    private final String diagnosticLogComponentId;

    protected AbstractOTPProgressiveEnrollmentHandler(String authenticatorName, String errorCodePrefix,
                                                      String diagnosticLogComponentId) {

        this.authenticatorName = authenticatorName;
        this.errorCodePrefix = errorCodePrefix;
        this.diagnosticLogComponentId = diagnosticLogComponentId;
    }

    /**
     * Handle the enrollment before the OTP flow is initiated.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @return True if the user is redirected, false if the OTP flow should continue.
     * @throws AuthenticationFailedException If an error occurred.
     */
    public boolean handleInitiation(HttpServletRequest request, HttpServletResponse response,
                                    AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser user = resolveUserEligibleForEnrollment(context);
        if (user == null) {
            clearEnrollment(context);
            return false;
        }
        if (isValueSubmission(request, context)) {
            return handleSubmittedValue(request, response, context, user);
        }
        if (StringUtils.isNotBlank(getPendingValue(context))) {
            return false;
        }
        String errorQueryParams = (String) context.getProperty(contextKey(ENROLLMENT_ERROR));
        context.removeProperty(contextKey(ENROLLMENT_ERROR));
        redirectToEnrollmentPage(request, response, context, errorQueryParams);
        return true;
    }

    /**
     * Check whether the request submits a value for enrollment.
     *
     * @param request HttpServletRequest.
     * @param context AuthenticationContext.
     * @return True if a value is submitted for enrollment.
     */
    public boolean isValueSubmission(HttpServletRequest request, AuthenticationContext context) {

        return authenticatorName.equals(context.getCurrentAuthenticator())
                && StringUtils.isNotBlank(request.getParameter(getValueParameterName()))
                && !isOTPSubmissionOrResend(request)
                && isEnrollmentInProgress(context);
    }

    private boolean isEnrollmentInProgress(AuthenticationContext context) {

        return isAwaitingValue(context) || StringUtils.isNotBlank(getPendingValue(context));
    }

    /**
     * Check whether a value is requested from the user.
     *
     * @param context AuthenticationContext.
     * @return True if a value is requested from the user.
     */
    public boolean isAwaitingValue(AuthenticationContext context) {

        return Boolean.TRUE.equals(context.getProperty(contextKey(AWAITING_VALUE)));
    }

    /**
     * Get the value pending enrollment, to which the OTP is sent.
     *
     * @param context AuthenticationContext.
     * @return The value pending enrollment, or null if none.
     */
    public String getPendingValue(AuthenticationContext context) {

        Object value = context.getProperty(contextKey(PENDING_VALUE));
        return value instanceof String ? (String) value : null;
    }

    /**
     * Record the value to which the OTP is sent, so that the OTP can enroll only that value.
     *
     * @param context AuthenticationContext.
     * @param sentTo  Value to which the OTP is sent.
     */
    public void recordOTPSent(AuthenticationContext context, String sentTo) {

        if (StringUtils.isNotBlank(getPendingValue(context))) {
            context.setProperty(contextKey(OTP_SENT_TO_VALUE), sentTo);
        }
    }

    /**
     * Save the pending value as verified. Call only after the OTP is verified; other codes, such as backup codes, must
     * not be accepted while a value is pending.
     *
     * @param context AuthenticationContext.
     * @throws AuthenticationFailedException If the value could not be saved.
     */
    public void completeEnrollment(AuthenticationContext context) throws AuthenticationFailedException {

        String value = getPendingValue(context);
        if (StringUtils.isBlank(value)) {
            return;
        }
        Object otpSentTo = context.getProperty(contextKey(OTP_SENT_TO_VALUE));
        context.removeProperty(contextKey(PENDING_VALUE));
        context.removeProperty(contextKey(AWAITING_VALUE));
        context.removeProperty(contextKey(OTP_SENT_TO_VALUE));

        AuthenticatedUser user = getSubjectAuthenticatedUser(context);
        if (user == null || user.isFederatedUser()) {
            clearEnrollment(context);
            return;
        }
        if (!value.equals(otpSentTo)) {
            context.setProperty(contextKey(ENROLLMENT_ERROR), getErrorQueryParams(ENROLLMENT_FAILED_MESSAGE_SUFFIX));
            logEnrollment("The value is not enrolled since the verified OTP was not sent to that value.", user, null,
                    DiagnosticLog.ResultStatus.FAILED);
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_VALUE, null,
                    user.getLoggableMaskedUserId());
        }
        String existingValue = getValueFromUserStore(user);
        if (StringUtils.isNotBlank(existingValue)) {
            if (existingValue.equals(value)) {
                clearEnrollment(context);
                return;
            }
            // A value configured while the enrollment was in progress is never replaced.
            logEnrollment("The value is not enrolled since another value was configured for the user while the " +
                    "enrollment was in progress.", user, null, DiagnosticLog.ResultStatus.FAILED);
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ENROLLMENT_VALUE_ALREADY_CONFIGURED, null,
                    user.getLoggableMaskedUserId());
        }

        Map<String, String> claims = new HashMap<>();
        claims.put(getValueClaimUri(), value);
        claims.put(getVerifiedClaimUri(), Boolean.TRUE.toString());
        UserStoreManager userStoreManager = getUserStoreManager(user);
        try {
            skipVerificationOnUpdate();
            userStoreManager.setUserClaimValues(
                    MultitenantUtils.getTenantAwareUsername(user.toFullQualifiedUsername()), claims, null);
        } catch (UserStoreException e) {
            context.setProperty(contextKey(ENROLLMENT_ERROR), getErrorQueryParams(ENROLLMENT_FAILED_MESSAGE_SUFFIX));
            logEnrollment("Failed to save the verified value to the user profile.", user, null,
                    DiagnosticLog.ResultStatus.FAILED);
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_VALUE, e,
                    user.getLoggableMaskedUserId());
        } finally {
            clearVerificationSkip();
        }
        clearEnrollment(context);
        logEnrollment("The value is enrolled successfully.", user, value, DiagnosticLog.ResultStatus.SUCCESS);
    }

    /**
     * @return URI of the claim which holds the value, such as the mobile number claim.
     */
    protected abstract String getValueClaimUri();

    /**
     * @return URI of the claim which marks the value of the channel as verified.
     */
    protected abstract String getVerifiedClaimUri();

    /**
     * @return Name of the request parameter which carries the submitted value.
     */
    protected abstract String getValueParameterName();

    /**
     * @return Prefix of the error message keys shown to the user.
     */
    protected abstract String getMessageKeyPrefix();

    /**
     * @return Name of the organization setting which enables the enrollment.
     */
    protected abstract String getEnrollmentEnabledSettingKey();

    /**
     * @return Name of the organization setting which holds the regex of the value.
     */
    protected abstract String getValueRegexSettingKey();

    /**
     * @return Regex used when no regex is configured for the organization.
     */
    protected abstract String getDefaultValueRegex();

    /**
     * @return URL of the page which requests the value.
     * @throws AuthenticationFailedException If an error occurred while building the URL.
     */
    protected abstract String getEnrollmentPageUrl() throws AuthenticationFailedException;

    /**
     * @param context AuthenticationContext.
     * @return URL of the error page of the authenticator.
     * @throws AuthenticationFailedException If an error occurred while building the URL.
     */
    protected abstract String getErrorPageUrl(AuthenticationContext context) throws AuthenticationFailedException;

    /**
     * Invalidate the OTP held in the context.
     *
     * @param context AuthenticationContext.
     */
    protected abstract void invalidateOTP(AuthenticationContext context);

    /**
     * Skip the verification triggered on updating the value claim, since the OTP already verified the value.
     */
    protected abstract void skipVerificationOnUpdate();

    /**
     * Clear the state set by {@link #skipVerificationOnUpdate()}.
     */
    protected abstract void clearVerificationSkip();

    /**
     * Normalize a submitted value. Trims whitespaces by default.
     *
     * @param value Value submitted by the user.
     * @return Normalized value, or null if the value is blank.
     */
    protected String normalize(String value) {

        return StringUtils.trimToNull(value);
    }

    /**
     * Validate a submitted value against the maximum length and the regex. Override to add channel specific checks.
     *
     * @param value   Normalized value.
     * @param context AuthenticationContext.
     * @return Error message key suffix if the value is not valid, null otherwise.
     * @throws AuthenticationFailedException If an error occurred while validating the value.
     */
    protected String validateValue(String value, AuthenticationContext context) throws AuthenticationFailedException {

        if (value.length() > getMaxValueLength()) {
            return INVALID_VALUE_MESSAGE_SUFFIX;
        }
        String tenantDomain = context.getTenantDomain();
        String regex = getOrganizationSetting(getValueRegexSettingKey(), tenantDomain);
        if (StringUtils.isBlank(regex)) {
            regex = getDefaultValueRegex();
        }
        try {
            return Pattern.matches(regex, value) ? null : INVALID_VALUE_MESSAGE_SUFFIX;
        } catch (PatternSyntaxException e) {
            // Fail closed, so that the restriction intended by the regex is not bypassed.
            LOG.error(String.format("The enrollment regex configured for %s in tenant: %s is not valid. Hence, " +
                    "values cannot be enrolled.", authenticatorName, tenantDomain), e);
            return INVALID_VALUE_MESSAGE_SUFFIX;
        }
    }

    /**
     * @return Maximum length of a submitted value.
     */
    protected int getMaxValueLength() {

        return EnrollmentConstants.DEFAULT_MAX_VALUE_LENGTH;
    }

    /**
     * @return Maximum number of different values that can be submitted in an authentication flow.
     */
    protected int getMaxEnrollmentAttempts() {

        return EnrollmentConstants.DEFAULT_MAX_ENROLLMENT_ATTEMPTS;
    }

    /**
     * Check whether the request submits or resends an OTP.
     *
     * @param request HttpServletRequest.
     * @return True if the request submits or resends an OTP.
     */
    protected boolean isOTPSubmissionOrResend(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(AuthenticatorConstants.CODE))
                || Boolean.parseBoolean(request.getParameter(AuthenticatorConstants.RESEND));
    }

    /**
     * Check whether the OTP authenticator is the first factor.
     *
     * @param context AuthenticationContext.
     * @return True if the authenticator is the first factor.
     */
    protected boolean isFirstFactor(AuthenticationContext context) {

        return context.getCurrentStep() == 1 || AuthenticatorUtils.isPreviousIdPAuthenticationFlowHandler(context);
    }

    /**
     * Get a parameter of the authenticator from the server configuration.
     *
     * @param parameterName Name of the parameter.
     * @return Value of the parameter, or null if not configured.
     */
    protected String getAuthenticatorParameter(String parameterName) {

        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(authenticatorName);
        if (authenticatorConfig == null || MapUtils.isEmpty(authenticatorConfig.getParameterMap())) {
            return null;
        }
        return authenticatorConfig.getParameterMap().get(parameterName);
    }

    private Map<String, String> getRuntimeParams(AuthenticationContext context) {

        Map<String, String> runtimeParams = new HashMap<>();
        Map<String, String> commonParams =
                context.getAuthenticatorParams(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS);
        if (MapUtils.isNotEmpty(commonParams)) {
            runtimeParams.putAll(commonParams);
        }
        Map<String, String> authenticatorParams = context.getAuthenticatorParams(authenticatorName);
        if (MapUtils.isNotEmpty(authenticatorParams)) {
            runtimeParams.putAll(authenticatorParams);
        }
        return runtimeParams;
    }

    private String getOrganizationSetting(String settingKey, String tenantDomain)
            throws AuthenticationFailedException {

        try {
            Property[] settings = AuthenticatorDataHolder.getIdentityGovernanceService()
                    .getConfiguration(new String[]{settingKey}, tenantDomain);
            return settings == null || settings.length == 0 ? null : settings[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG, e);
        }
    }

    private AuthenticatedUser resolveUserEligibleForEnrollment(AuthenticationContext context)
            throws AuthenticationFailedException {

        if (isFirstFactor(context)) {
            return null;
        }
        AuthenticatedUser user = getSubjectAuthenticatedUser(context);
        if (user == null || user.isFederatedUser() || !isEnrollmentEnabled(context)) {
            return null;
        }
        if (StringUtils.isNotBlank(getValueFromUserStore(user))) {
            return null;
        }
        if (isAccountLocked(user)) {
            return null;
        }
        return user;
    }

    private boolean isEnrollmentEnabled(AuthenticationContext context) throws AuthenticationFailedException {

        // An application can only opt out from the authentication script.
        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (MapUtils.isNotEmpty(runtimeParams)) {
            String enrolUser = runtimeParams.get(EnrollmentConstants.ENROL_USER_IN_AUTHENTICATION_FLOW);
            if (StringUtils.isNotBlank(enrolUser) && !Boolean.parseBoolean(enrolUser)) {
                return false;
            }
        }
        return Boolean.parseBoolean(
                getOrganizationSetting(getEnrollmentEnabledSettingKey(), context.getTenantDomain()));
    }

    private boolean handleSubmittedValue(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context, AuthenticatedUser user)
            throws AuthenticationFailedException {

        String value = normalize(request.getParameter(getValueParameterName()));
        String validationError = StringUtils.isBlank(value) ? INVALID_VALUE_MESSAGE_SUFFIX :
                validateValue(value, context);
        if (validationError != null) {
            logEnrollment("The value submitted for enrollment is not valid.", user, null,
                    DiagnosticLog.ResultStatus.FAILED);
            redirectToEnrollmentPage(request, response, context, getErrorQueryParams(validationError));
            return true;
        }
        if (!value.equals(getPendingValue(context))) {
            int enrollmentAttempts = getEnrollmentAttempts(context);
            if (enrollmentAttempts >= getMaxEnrollmentAttempts()) {
                logEnrollment("The maximum number of values allowed to be submitted for enrollment is exceeded.",
                        user, null, DiagnosticLog.ResultStatus.FAILED);
                invalidateOTP(context);
                context.removeProperty(contextKey(OTP_SENT_TO_VALUE));
                context.removeProperty(contextKey(AWAITING_VALUE));
                context.removeProperty(contextKey(PENDING_VALUE));
                redirectToErrorPage(request, response, context,
                        getErrorQueryParams(ATTEMPTS_EXCEEDED_MESSAGE_SUFFIX));
                return true;
            }
            context.setProperty(contextKey(ENROLLMENT_ATTEMPTS), enrollmentAttempts + 1);
            context.setProperty(contextKey(PENDING_VALUE), value);
            // An OTP sent to an earlier value must not verify the new value.
            invalidateOTP(context);
            context.removeProperty(contextKey(OTP_SENT_TO_VALUE));
        }
        context.removeProperty(contextKey(AWAITING_VALUE));
        context.setRetrying(false);
        logEnrollment("Sending an OTP to verify the value submitted for enrollment.", user, value,
                DiagnosticLog.ResultStatus.SUCCESS);
        return false;
    }

    private void redirectToEnrollmentPage(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context, String errorQueryParams)
            throws AuthenticationFailedException {

        StringBuilder queryParams = new StringBuilder(FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier()))
                .append(AuthenticatorConstants.AUTHENTICATORS_QUERY_PARAM).append(authenticatorName)
                .append(AuthenticatorUtils.getMultiOptionURIQueryString(request));
        if (StringUtils.isNotBlank(errorQueryParams)) {
            queryParams.append(errorQueryParams);
        }
        context.setProperty(contextKey(AWAITING_VALUE), true);
        try {
            response.sendRedirect(FrameworkUtils.appendQueryParamsStringToUrl(getEnrollmentPageUrl(),
                    queryParams.toString()));
        } catch (IOException e) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ENROLLMENT_PAGE, e);
        }
    }

    private void redirectToErrorPage(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context, String errorQueryParams)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())
                + AuthenticatorConstants.AUTHENTICATORS_QUERY_PARAM + authenticatorName + errorQueryParams
                + AuthenticatorUtils.getMultiOptionURIQueryString(request);
        try {
            response.sendRedirect(FrameworkUtils.appendQueryParamsStringToUrl(getErrorPageUrl(context),
                    queryParams));
        } catch (IOException e) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE, e);
        }
    }

    private void clearEnrollment(AuthenticationContext context) {

        if (context.getProperty(contextKey(OTP_SENT_TO_VALUE)) != null) {
            // An OTP sent to a discontinued value must not complete the authentication.
            invalidateOTP(context);
        }
        context.removeProperty(contextKey(AWAITING_VALUE));
        context.removeProperty(contextKey(PENDING_VALUE));
        context.removeProperty(contextKey(OTP_SENT_TO_VALUE));
        context.removeProperty(contextKey(ENROLLMENT_ATTEMPTS));
        context.removeProperty(contextKey(ENROLLMENT_ERROR));
    }

    private int getEnrollmentAttempts(AuthenticationContext context) {

        Object attempts = context.getProperty(contextKey(ENROLLMENT_ATTEMPTS));
        return attempts instanceof Integer ? (Integer) attempts : 0;
    }

    private String contextKey(String suffix) {

        return authenticatorName + suffix;
    }

    private String getErrorQueryParams(String messageKeySuffix) {

        return AUTH_FAILURE_QUERY_PARAMS + getMessageKeyPrefix() + messageKeySuffix;
    }

    private static AuthenticatedUser getSubjectAuthenticatedUser(AuthenticationContext context) {

        if (context.getSequenceConfig() == null || context.getSequenceConfig().getStepMap() == null) {
            return null;
        }
        for (StepConfig stepConfig : context.getSequenceConfig().getStepMap().values()) {
            if (stepConfig.isSubjectAttributeStep() && stepConfig.getAuthenticatedUser() != null) {
                return new AuthenticatedUser(stepConfig.getAuthenticatedUser());
            }
        }
        return null;
    }

    private boolean isAccountLocked(AuthenticatedUser user) throws AuthenticationFailedException {

        try {
            return AuthenticatorDataHolder.getAccountLockService().isAccountLocked(user.getUserName(),
                    user.getTenantDomain(), user.getUserStoreDomain());
        } catch (AccountLockServiceException e) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_GETTING_ACCOUNT_STATE, e,
                    user.getLoggableMaskedUserId());
        }
    }

    private String getValueFromUserStore(AuthenticatedUser user) throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(
                    MultitenantUtils.getTenantAwareUsername(user.toFullQualifiedUsername()),
                    new String[]{getValueClaimUri()}, null);
            return claimValues == null ? null : claimValues.get(getValueClaimUri());
        } catch (UserStoreException e) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_CLAIM, e,
                    getValueClaimUri(), user.getLoggableMaskedUserId());
        }
    }

    private UserStoreManager getUserStoreManager(AuthenticatedUser user) throws AuthenticationFailedException {

        String tenantDomain = user.getTenantDomain();
        UserRealm userRealm;
        try {
            userRealm = AuthenticatorDataHolder.getRealmService().getTenantUserRealm(
                    IdentityTenantUtil.getTenantId(tenantDomain));
        } catch (UserStoreException e) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM, e,
                    tenantDomain);
        }
        if (userRealm == null) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM, null,
                    tenantDomain);
        }
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER,
                        null, user.getLoggableMaskedUserId());
            }
            String userStoreDomain = user.getUserStoreDomain();
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw handleError(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, e,
                    user.getLoggableMaskedUserId());
        }
    }

    private AuthenticationFailedException handleError(AuthenticatorConstants.ErrorMessages error, Throwable throwable,
                                                      Object... data) {

        String errorCode = errorCodePrefix + "-" + error.getCode();
        String message = data == null || data.length == 0 ? error.getMessage() :
                String.format(error.getMessage(), data);
        return throwable == null ? new AuthenticationFailedException(errorCode, message) :
                new AuthenticationFailedException(errorCode, message, throwable);
    }

    private void logEnrollment(String resultMessage, AuthenticatedUser user, String value,
                               DiagnosticLog.ResultStatus resultStatus) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                diagnosticLogComponentId, EnrollmentConstants.ENROLL_ACTION_ID);
        diagnosticLogBuilder
                .resultMessage(resultMessage)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(resultStatus)
                .inputParam(LogConstants.InputKeys.AUTHENTICATOR_NAME, authenticatorName);
        if (user != null) {
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER, user.getLoggableMaskedUserId());
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.TENANT_DOMAIN, user.getTenantDomain());
        }
        if (StringUtils.isNotBlank(value)) {
            diagnosticLogBuilder.inputParam(EnrollmentConstants.ENROLLMENT_VALUE_LOG_KEY,
                    AuthenticatorUtils.maskIfRequired(value));
        }
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }
}
