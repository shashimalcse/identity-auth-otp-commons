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
 * Lets a user who does not have a value for an OTP channel, such as a mobile number, enroll one during the
 * authentication flow. The user is requested to enter a value, the OTP authenticator sends an OTP to it, and the value
 * is saved to the user profile as verified only after the OTP sent to that value is verified.
 * <p>
 * An OTP authenticator extends this class to supply the details of its channel, such as the claim which holds the
 * value, and calls the handler at the following points:
 * <ul>
 *     <li>{@link #handleInitiation} before initiating the OTP flow,</li>
 *     <li>{@link #isValueSubmission} while resolving the scenario of a request,</li>
 *     <li>{@link #getPendingValue} while resolving the value to send the OTP to, when the user has no value,</li>
 *     <li>{@link #recordOTPSent} when sending the OTP, and</li>
 *     <li>{@link #completeEnrollment} after the OTP is verified.</li>
 * </ul>
 * While {@link #isAwaitingValue} is true, app native authentication should request the value parameter instead of the
 * OTP. The OTP authenticator owns sending and verifying the OTP. A handler is shared across authentication requests.
 * Hence, it must be stateless, keeping the state of an enrollment in the authentication context.
 */
public abstract class AbstractOTPProgressiveEnrollmentHandler {

    private static final Log LOG = LogFactory.getLog(AbstractOTPProgressiveEnrollmentHandler.class);

    private final String authenticatorName;
    private final String errorCodePrefix;
    private final String diagnosticLogComponentId;

    /**
     * @param authenticatorName        Name of the OTP authenticator.
     * @param errorCodePrefix          Error code prefix of the OTP authenticator.
     * @param diagnosticLogComponentId Component ID used for the diagnostic logs of the enrollment.
     */
    protected AbstractOTPProgressiveEnrollmentHandler(String authenticatorName, String errorCodePrefix,
                                                      String diagnosticLogComponentId) {

        this.authenticatorName = authenticatorName;
        this.errorCodePrefix = errorCodePrefix;
        this.diagnosticLogComponentId = diagnosticLogComponentId;
    }

    /**
     * Handle the enrollment before the OTP flow is initiated. A user who is eligible is requested to enter a value,
     * and a submitted value is kept as pending enrollment so that the OTP is sent to it.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @return True if the request is handled by redirecting the user, false if the OTP flow should continue.
     * @throws AuthenticationFailedException If an error occurred while handling the enrollment.
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
            // An OTP is sent to the value pending enrollment. Resending and verifying it continue as usual.
            return false;
        }
        String errorQueryParams = (String) context.getProperty(contextKey(ENROLLMENT_ERROR));
        context.removeProperty(contextKey(ENROLLMENT_ERROR));
        redirectToEnrollmentPage(request, response, context, errorQueryParams);
        return true;
    }

    /**
     * Check whether the request submits a value for enrollment, while a value is requested from the user or is
     * pending enrollment.
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

    /**
     * @param context AuthenticationContext.
     * @return True if a value is requested from the user or is pending enrollment.
     */
    private boolean isEnrollmentInProgress(AuthenticationContext context) {

        return isAwaitingValue(context) || StringUtils.isNotBlank(getPendingValue(context));
    }

    /**
     * @param context AuthenticationContext.
     * @return True if a value is requested from the user.
     */
    public boolean isAwaitingValue(AuthenticationContext context) {

        return Boolean.TRUE.equals(context.getProperty(contextKey(AWAITING_VALUE)));
    }

    /**
     * Get the value pending enrollment. The OTP authenticator sends the OTP to this value when the user does not have
     * a value, and the value is saved to the profile only after that OTP is verified.
     *
     * @param context AuthenticationContext.
     * @return The value pending enrollment, or null if none.
     */
    public String getPendingValue(AuthenticationContext context) {

        Object value = context.getProperty(contextKey(PENDING_VALUE));
        return value instanceof String ? (String) value : null;
    }

    /**
     * Record the value to which an OTP is sent, so that the OTP can enroll only that value.
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
     * Save the value pending enrollment to the user profile as verified. Call this only after the OTP sent by the
     * authenticator is verified, since possession of the value is proven only by that OTP. Hence, an authenticator
     * which accepts other codes, such as backup codes, must not accept them while a value is pending enrollment.
     * Nothing is saved if the OTP was not sent to the value.
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
        // The verified OTP is consumed. Hence, the value cannot be saved through another attempt with the same OTP.
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
        // The value is verified by the OTP sent to it.
        claims.put(getVerifiedClaimUri(), Boolean.TRUE.toString());
        UserStoreManager userStoreManager = getUserStoreManager(user);
        try {
            skipVerificationOnUpdate();
            userStoreManager.setUserClaimValues(
                    MultitenantUtils.getTenantAwareUsername(user.toFullQualifiedUsername()), claims, null);
        } catch (UserStoreException e) {
            // The reason is not sent to the user, since it is not guaranteed to be free of internal details.
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
     * @return URI of the claim which holds the value of the channel, such as the mobile number claim.
     */
    protected abstract String getValueClaimUri();

    /**
     * @return URI of the claim which marks the value of the channel as verified.
     */
    protected abstract String getVerifiedClaimUri();

    /**
     * @return Name of the request parameter which carries the value submitted for enrollment.
     */
    protected abstract String getValueParameterName();

    /**
     * Get the prefix of the error message keys shown to the user. The keys are formed by appending
     * {@link EnrollmentConstants#INVALID_VALUE_MESSAGE_SUFFIX},
     * {@link EnrollmentConstants#ENROLLMENT_FAILED_MESSAGE_SUFFIX},
     * {@link EnrollmentConstants#ATTEMPTS_EXCEEDED_MESSAGE_SUFFIX}, or a suffix returned by {@link #validateValue}.
     *
     * @return Prefix of the error message keys.
     */
    protected abstract String getMessageKeyPrefix();

    /**
     * @return Name of the organization setting which enables enrolling a value during the authentication flow.
     */
    protected abstract String getEnrollmentEnabledSettingKey();

    /**
     * @return Name of the organization setting which holds the regex a submitted value should match.
     */
    protected abstract String getValueRegexSettingKey();

    /**
     * @return Regex a submitted value should match when no regex is configured for the organization.
     */
    protected abstract String getDefaultValueRegex();

    /**
     * @return URL of the page which requests a value from the user.
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
     * Invalidate the OTP held in the context, so that it can no longer complete the authentication.
     *
     * @param context AuthenticationContext.
     */
    protected abstract void invalidateOTP(AuthenticationContext context);

    /**
     * Skip the verification which is otherwise initiated when the value claim is updated, since the value is
     * already verified by the OTP. {@link #clearVerificationSkip()} is always called after the update.
     */
    protected abstract void skipVerificationOnUpdate();

    /**
     * Clear the state set by {@link #skipVerificationOnUpdate()}.
     */
    protected abstract void clearVerificationSkip();

    /**
     * Remove the formatting characters commonly used with values of the channel. Leading and trailing whitespaces
     * are removed by default.
     *
     * @param value Value submitted by the user.
     * @return Normalized value, or null if the value is blank.
     */
    protected String normalize(String value) {

        return StringUtils.trimToNull(value);
    }

    /**
     * Validate a value submitted for enrollment. By default, the value must not exceed the maximum length and must match
     * the regex configured for the organization, or the default regex of the channel when none is configured. Override
     * to add channel specific checks, calling this method first to keep the default checks.
     *
     * @param value   Normalized value, which is not blank.
     * @param context AuthenticationContext.
     * @return Suffix of the error message key shown to the user, such as
     * {@link EnrollmentConstants#INVALID_VALUE_MESSAGE_SUFFIX}, if the value is not valid. Null if the value is valid.
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
            // No value is accepted, so that a restriction intended by the configured regex is never bypassed.
            LOG.error(String.format("The enrollment regex configured for %s in tenant: %s is not valid. Hence, " +
                    "values cannot be enrolled.", authenticatorName, tenantDomain), e);
            return INVALID_VALUE_MESSAGE_SUFFIX;
        }
    }

    /**
     * @return Maximum length of a submitted value, checked before matching the regex.
     */
    protected int getMaxValueLength() {

        return EnrollmentConstants.DEFAULT_MAX_VALUE_LENGTH;
    }

    /**
     * @return Maximum number of different values that a user can submit for enrollment in an authentication flow.
     */
    protected int getMaxEnrollmentAttempts() {

        return EnrollmentConstants.DEFAULT_MAX_ENROLLMENT_ATTEMPTS;
    }

    /**
     * Check whether the request submits or resends an OTP, in which case it is not treated as a value submission.
     *
     * @param request HttpServletRequest.
     * @return True if the request submits or resends an OTP.
     */
    protected boolean isOTPSubmissionOrResend(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(AuthenticatorConstants.CODE))
                || Boolean.parseBoolean(request.getParameter(AuthenticatorConstants.RESEND));
    }

    /**
     * Check whether the OTP authenticator is the first factor of the authentication flow, in which case no user is
     * identified to enroll a value for.
     *
     * @param context AuthenticationContext.
     * @return True if the authenticator is the first factor.
     */
    protected boolean isFirstFactor(AuthenticationContext context) {

        return context.getCurrentStep() == 1 || AuthenticatorUtils.isPreviousIdPAuthenticationFlowHandler(context);
    }

    /**
     * Get a parameter configured for the authenticator in the server configuration.
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

    /**
     * Get the parameters set for the authenticator from the authentication script, along with the common options.
     *
     * @param context AuthenticationContext.
     * @return Runtime parameters of the authenticator.
     */
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

    /**
     * Get a setting of the organization, configured through the connector of the authenticator.
     *
     * @param settingKey   Name of the setting.
     * @param tenantDomain Tenant domain.
     * @return Value of the setting, or null if not configured.
     * @throws AuthenticationFailedException If an error occurred while getting the setting.
     */
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

    /**
     * Resolve the user, if the user is eligible to enroll a value in the current authentication flow.
     *
     * @param context AuthenticationContext.
     * @return The user if eligible to enroll a value, null otherwise.
     * @throws AuthenticationFailedException If an error occurred while resolving the user.
     */
    private AuthenticatedUser resolveUserEligibleForEnrollment(AuthenticationContext context)
            throws AuthenticationFailedException {

        // A value is enrolled only for a user who is identified by a preceding authentication step.
        if (isFirstFactor(context)) {
            return null;
        }
        AuthenticatedUser user = getSubjectAuthenticatedUser(context);
        // Attributes of federated users are managed by the federated identity provider.
        if (user == null || user.isFederatedUser() || !isEnrollmentEnabled(context)) {
            return null;
        }
        // A value configured for the user is never replaced from the authentication flow.
        if (StringUtils.isNotBlank(getValueFromUserStore(user))) {
            return null;
        }
        if (isAccountLocked(user)) {
            return null;
        }
        return user;
    }

    /**
     * Check whether enrollment is enabled. An application can opt out from the authentication script, but cannot
     * enable the enrollment when it is not enabled for the organization.
     *
     * @param context AuthenticationContext.
     * @return True if enrollment is enabled.
     * @throws AuthenticationFailedException If an error occurred while getting the configuration.
     */
    private boolean isEnrollmentEnabled(AuthenticationContext context) throws AuthenticationFailedException {

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

    /**
     * Handle a value submitted for enrollment. A valid value is kept as pending enrollment, so that the OTP is sent to
     * it. A value is never saved to the user profile from here.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @param user     User who enrolls the value.
     * @return True if the request is handled by redirecting the user, false if an OTP should be sent to the value.
     * @throws AuthenticationFailedException If an error occurred while handling the value.
     */
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
            /* Invalidates an OTP sent to an earlier value. Otherwise, it could verify the new value if sending an OTP
             to the new value is not allowed, such as when the resend limit is exceeded. */
            invalidateOTP(context);
            context.removeProperty(contextKey(OTP_SENT_TO_VALUE));
        }
        context.removeProperty(contextKey(AWAITING_VALUE));
        // An OTP is sent to the submitted value afresh. Hence, failures of an earlier OTP are not carried forward.
        context.setRetrying(false);
        logEnrollment("Sending an OTP to verify the value submitted for enrollment.", user, value,
                DiagnosticLog.ResultStatus.SUCCESS);
        return false;
    }

    /**
     * Redirect the user to the page which requests a value.
     *
     * @param request          HttpServletRequest.
     * @param response         HttpServletResponse.
     * @param context          AuthenticationContext.
     * @param errorQueryParams Query params of the error to be shown on the page. Can be null.
     * @throws AuthenticationFailedException If an error occurred while redirecting.
     */
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

    /**
     * Redirect the user to the error page, when the enrollment cannot be continued.
     *
     * @param request          HttpServletRequest.
     * @param response         HttpServletResponse.
     * @param context          AuthenticationContext.
     * @param errorQueryParams Query params of the error to be shown on the page.
     * @throws AuthenticationFailedException If an error occurred while redirecting.
     */
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
            /* An OTP sent to a value pending enrollment must not complete the authentication once the enrollment is
             discontinued, such as when a value is configured for the user in the meantime. */
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

    /**
     * Get the user identified by the subject attribute step of the authentication flow.
     *
     * @param context AuthenticationContext.
     * @return The user, or null if no user is identified yet.
     */
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

    /**
     * Record the progress of an enrollment as a diagnostic log.
     *
     * @param resultMessage Message describing the progress.
     * @param user          User who enrolls the value.
     * @param value         Value related to the progress. Can be null.
     * @param resultStatus  Result status of the diagnostic log.
     */
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
