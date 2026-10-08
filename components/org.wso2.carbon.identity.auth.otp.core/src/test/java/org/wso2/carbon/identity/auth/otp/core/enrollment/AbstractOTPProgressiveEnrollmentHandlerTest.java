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

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Tests enrolling an OTP channel value during the authentication flow, for a user who does not have one.
 */
public class AbstractOTPProgressiveEnrollmentHandlerTest {

    private static final String AUTHENTICATOR = "test-otp-authenticator";
    private static final String VALUE_PARAM = "TEST_VALUE";
    private static final String VALUE_CLAIM = "http://wso2.org/claims/mobile";
    private static final String VERIFIED_CLAIM = "http://wso2.org/claims/identity/phoneVerified";
    private static final String MESSAGE_PREFIX = "test.otp.value";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    private static final String ENROLLMENT_PAGE = "https://localhost:9443/authenticationendpoint/enroll.jsp";
    private static final String ERROR_PAGE = "https://localhost:9443/authenticationendpoint/error.jsp";
    private static final String VALUE = "+94771234567";
    private static final String OTHER_VALUE = "+94777654321";
    private static final String OTP = "otp";
    private static final String ENABLED_SETTING = "TestOTP.EnrolUserInAuthenticationFlow";
    private static final String REGEX_SETTING = "TestOTP.ValueRegex";

    private TestHandler handler;
    private AuthenticationContext context;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AbstractUserStoreManager userStoreManager;
    private AccountLockService accountLockService;
    private Map<String, String> userClaims;
    private Map<String, String> organizationSettings;
    private IdentityGovernanceService governanceService;

    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<LoggerUtils> loggerUtils;

    @BeforeMethod
    public void setUp() throws Exception {

        handler = new TestHandler(AUTHENTICATOR);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        userClaims = new HashMap<>();
        organizationSettings = new HashMap<>();
        organizationSettings.put(ENABLED_SETTING, "true");

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(any(), any(), any()))
                .thenReturn("sessionDataKey=session-data-key");
        frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

        userStoreManager = mock(AbstractUserStoreManager.class);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), isNull()))
                .thenAnswer(invocation -> new HashMap<>(userClaims));
        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        RealmService realmService = mock(RealmService.class);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        AuthenticatorDataHolder.setRealmService(realmService);
        accountLockService = mock(AccountLockService.class);
        AuthenticatorDataHolder.setAccountLockService(accountLockService);
        governanceService = mock(IdentityGovernanceService.class);
        when(governanceService.getConfiguration(any(String[].class), eq(TENANT_DOMAIN))).thenAnswer(invocation -> {
            String settingKey = ((String[]) invocation.getArgument(0))[0];
            if (!organizationSettings.containsKey(settingKey)) {
                return new Property[0];
            }
            Property setting = new Property();
            setting.setName(settingKey);
            setting.setValue(organizationSettings.get(settingKey));
            return new Property[]{setting};
        });
        AuthenticatorDataHolder.setIdentityGovernanceService(governanceService);

        context = buildContext(buildLocalUser());
    }

    @AfterMethod
    public void tearDown() {

        frameworkUtils.close();
        identityTenantUtil.close();
        loggerUtils.close();
    }

    @Test
    public void testRedirectToEnrollmentPageForUserWithoutValue() throws Exception {

        assertTrue(handler.handleInitiation(request, response, context));

        String redirectUrl = captureRedirectUrl();
        assertTrue(redirectUrl.startsWith(ENROLLMENT_PAGE));
        assertTrue(redirectUrl.contains("&authenticators=" + AUTHENTICATOR),
                "The authenticator is required on the page URL for app native authentication.");
        assertFalse(redirectUrl.contains("authFailure"), "No error is expected when requesting a value.");
        assertTrue(handler.isAwaitingValue(context));
    }

    @Test
    public void testNoEnrollmentWhenDisabledForOrganization() throws Exception {

        organizationSettings.put(ENABLED_SETTING, "false");

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testApplicationCanOptOutFromScript() throws Exception {

        setRuntimeParam(AUTHENTICATOR, EnrollmentConstants.ENROL_USER_IN_AUTHENTICATION_FLOW, "false");

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testApplicationCannotEnableFromScriptWhenDisabledForOrganization() throws Exception {

        organizationSettings.put(ENABLED_SETTING, "false");
        setRuntimeParam(AUTHENTICATOR, EnrollmentConstants.ENROL_USER_IN_AUTHENTICATION_FLOW, "true");

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentWhenFirstFactor() throws Exception {

        context.setCurrentStep(1);

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentWithoutPrecedingAuthenticatedUser() throws Exception {

        context = buildContext(null);

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentForFederatedUser() throws Exception {

        AuthenticatedUser federatedUser = buildLocalUser();
        federatedUser.setFederatedUser(true);
        context = buildContext(federatedUser);

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentForLockedUser() throws Exception {

        when(accountLockService.isAccountLocked(anyString(), anyString(), anyString())).thenReturn(true);

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testExistingValueIsNeverReplaced() throws Exception {

        userClaims.put(VALUE_CLAIM, VALUE);
        setAwaitingValue();
        when(request.getParameter(VALUE_PARAM)).thenReturn(OTHER_VALUE);

        assertFalse(handler.handleInitiation(request, response, context));
        assertNull(handler.getPendingValue(context),
                "A submitted value must not be considered for a user who already has a value.");
        assertFalse(handler.isAwaitingValue(context));
    }

    @DataProvider
    public Object[][] invalidValues() {

        return new Object[][]{
                {"abcdefgh"},
                {"12345"},
                {"+9477123456789012345"},
                {"+94771234567;+94777654321"},
                {"+947712345678901234567890123456789"}
        };
    }

    @Test(dataProvider = "invalidValues")
    public void testInvalidValueIsRejectedBeforeSendingOtp(String value) throws Exception {

        setAwaitingValue();
        when(request.getParameter(VALUE_PARAM)).thenReturn(value);

        // True means the flow does not continue to send an OTP.
        assertTrue(handler.handleInitiation(request, response, context));

        String redirectUrl = captureRedirectUrl();
        assertTrue(redirectUrl.startsWith(ENROLLMENT_PAGE));
        assertTrue(redirectUrl.endsWith("&authFailure=true&authFailureMsg=" + MESSAGE_PREFIX + ".invalid"));
        assertNull(handler.getPendingValue(context));
    }

    @Test
    public void testValidValueIsKeptPendingUntilVerified() throws Exception {

        setAwaitingValue();
        context.setRetrying(true);
        when(request.getParameter(VALUE_PARAM)).thenReturn(" " + VALUE + " ");

        // False means the flow continues to send an OTP to the value.
        assertFalse(handler.handleInitiation(request, response, context));

        verify(response, never()).sendRedirect(anyString());
        assertEquals(handler.getPendingValue(context), VALUE);
        assertEquals(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS), 1);
        assertFalse(handler.isAwaitingValue(context));
        assertFalse(context.isRetrying(), "Failures of an earlier OTP must not be shown for the new value.");
        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testValueIsSubmittedOnlyWhileRequested() throws Exception {

        // A value in a request which was not prompted for is not taken.
        when(request.getParameter(VALUE_PARAM)).thenReturn(VALUE);

        assertTrue(handler.handleInitiation(request, response, context));

        assertTrue(captureRedirectUrl().startsWith(ENROLLMENT_PAGE));
        assertNull(handler.getPendingValue(context));
    }

    @Test
    public void testValueIsNotTakenAlongWithOtpCode() throws Exception {

        setPendingValue(VALUE);
        when(request.getParameter(VALUE_PARAM)).thenReturn(OTHER_VALUE);
        when(request.getParameter(AuthenticatorConstants.CODE)).thenReturn("123456");

        assertFalse(handler.handleInitiation(request, response, context));
        assertEquals(handler.getPendingValue(context), VALUE);
    }

    @Test
    public void testValueIsSubmittedOnlyToItsAuthenticator() {

        setAwaitingValue();
        context.setCurrentAuthenticator("another-authenticator");
        when(request.getParameter(VALUE_PARAM)).thenReturn(VALUE);

        assertFalse(handler.isValueSubmission(request, context));
    }

    @Test
    public void testChangingValueInvalidatesOtpSentToEarlierValue() throws Exception {

        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);
        context.setProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS, 1);
        context.setProperty(OTP, "123456");
        when(request.getParameter(VALUE_PARAM)).thenReturn(OTHER_VALUE);

        assertFalse(handler.handleInitiation(request, response, context));

        assertEquals(handler.getPendingValue(context), OTHER_VALUE);
        assertEquals(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS), 2);
        assertNull(context.getProperty(OTP), "An OTP sent to an earlier value must not verify the new value.");
        assertNull(context.getProperty(AUTHENTICATOR + EnrollmentConstants.OTP_SENT_TO_VALUE));
    }

    @Test
    public void testResubmittingSameValueDoesNotCountAsNewValue() throws Exception {

        setPendingValue(VALUE);
        context.setProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS, 1);
        when(request.getParameter(VALUE_PARAM)).thenReturn(VALUE);

        assertFalse(handler.handleInitiation(request, response, context));
        assertEquals(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS), 1);
    }

    @Test
    public void testNumberOfValuesPerFlowIsLimited() throws Exception {

        handler.maxEnrollmentAttempts = 2;
        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);
        context.setProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS, 2);
        context.setProperty(OTP, "123456");
        when(request.getParameter(VALUE_PARAM)).thenReturn(OTHER_VALUE);

        assertTrue(handler.handleInitiation(request, response, context));

        String redirectUrl = captureRedirectUrl();
        assertTrue(redirectUrl.startsWith(ERROR_PAGE));
        assertTrue(redirectUrl.contains("&authFailure=true&authFailureMsg=" + MESSAGE_PREFIX +
                ".enrollment.attempts.exceeded"));
        assertNull(handler.getPendingValue(context));
        assertNull(context.getProperty(OTP),
                "The OTP must not complete the authentication once the enrollment is discontinued.");
        assertEquals(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS), 2,
                "The count is kept so that the limit cannot be reset within the flow.");
    }

    @Test
    public void testDiscontinuedEnrollmentInvalidatesOtpOfPendingValue() throws Exception {

        // A value is configured for the user while an OTP sent to the pending value is not yet verified.
        userClaims.put(VALUE_CLAIM, OTHER_VALUE);
        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);
        context.setProperty(OTP, "123456");

        assertFalse(handler.handleInitiation(request, response, context));

        assertNull(context.getProperty(OTP),
                "An OTP sent to a value other than the configured value must not complete the authentication.");
        assertNull(handler.getPendingValue(context));
    }

    @Test
    public void testOtpOfRegularFlowIsKeptForUserWithValue() throws Exception {

        userClaims.put(VALUE_CLAIM, VALUE);
        context.setProperty(OTP, "123456");

        assertFalse(handler.handleInitiation(request, response, context));

        assertEquals(context.getProperty(OTP), "123456");
    }

    @Test
    public void testConfiguredRegexIsEnforced() throws Exception {

        organizationSettings.put(REGEX_SETTING, "^\\+94[0-9]{9}$");
        setAwaitingValue();
        when(request.getParameter(VALUE_PARAM)).thenReturn("+14155552671");

        assertTrue(handler.handleInitiation(request, response, context));
        assertTrue(captureRedirectUrl().endsWith(MESSAGE_PREFIX + ".invalid"));

        when(request.getParameter(VALUE_PARAM)).thenReturn(VALUE);
        assertFalse(handler.handleInitiation(request, response, context));
        assertEquals(handler.getPendingValue(context), VALUE);
    }

    @Test
    public void testInvalidConfiguredRegexRejectsAllValues() throws Exception {

        organizationSettings.put(REGEX_SETTING, "^([0-9");
        setAwaitingValue();
        when(request.getParameter(VALUE_PARAM)).thenReturn(VALUE);

        assertTrue(handler.handleInitiation(request, response, context));
        assertNull(handler.getPendingValue(context));
    }

    @Test
    public void testOtpFlowContinuesForPendingValue() throws Exception {

        setPendingValue(VALUE);

        // Resending or retrying the OTP continues as usual, for the value pending enrollment.
        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
        assertEquals(handler.getPendingValue(context), VALUE);
    }

    @Test
    public void testEnrollmentErrorIsShownOnceOnEnrollmentPage() throws Exception {

        String error = "&authFailure=true&authFailureMsg=" + MESSAGE_PREFIX + ".enrollment.failed";
        context.setProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ERROR, error);

        assertTrue(handler.handleInitiation(request, response, context));

        assertTrue(captureRedirectUrl().endsWith(error));
        assertNull(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ERROR));
    }

    @Test
    public void testOtpSentIsRecordedOnlyForPendingValue() {

        handler.recordOTPSent(context, VALUE);
        assertNull(context.getProperty(AUTHENTICATOR + EnrollmentConstants.OTP_SENT_TO_VALUE),
                "Sending an OTP to a configured value is not related to an enrollment.");

        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);
        assertEquals(context.getProperty(AUTHENTICATOR + EnrollmentConstants.OTP_SENT_TO_VALUE), VALUE);
    }

    @Test
    public void testVerifiedValueIsSavedAsVerified() throws Exception {

        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);
        context.setProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS, 1);

        doAnswer(invocation -> handler.events.add("update")).when(userStoreManager)
                .setUserClaimValues(anyString(), anyMap(), isNull());

        handler.completeEnrollment(context, true);

        ArgumentCaptor<Map<String, String>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(userStoreManager).setUserClaimValues(anyString(), claimsCaptor.capture(), isNull());
        Map<String, String> savedClaims = claimsCaptor.getValue();
        assertEquals(savedClaims.get(VALUE_CLAIM), VALUE);
        assertEquals(savedClaims.get(VERIFIED_CLAIM), "true");
        assertEquals(savedClaims.size(), 2);
        assertEquals(handler.events, Arrays.asList("skip", "update", "clear"),
                "The verification on update is skipped only around saving the verified value.");
        assertNull(handler.getPendingValue(context));
        assertNull(context.getProperty(AUTHENTICATOR + EnrollmentConstants.OTP_SENT_TO_VALUE));
        assertNull(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ATTEMPTS));
    }

    @Test
    public void testValueIsNotSavedWhenAuthenticationDidNotVerifyOtp() throws Exception {

        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);

        handler.completeEnrollment(context, false);

        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
        assertNull(handler.getPendingValue(context));
    }

    @Test
    public void testValueIsNotSavedWhenOtpWasNotSentToIt() throws Exception {

        setPendingValue(OTHER_VALUE);
        context.setProperty(AUTHENTICATOR + EnrollmentConstants.OTP_SENT_TO_VALUE, VALUE);

        assertCompletionFails(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_VALUE);

        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
        assertNull(handler.getPendingValue(context));
        assertEquals(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ERROR),
                "&authFailure=true&authFailureMsg=" + MESSAGE_PREFIX + ".enrollment.failed");
    }

    @Test
    public void testValueIsNotSavedWithoutAnOtpSentToIt() throws Exception {

        setPendingValue(VALUE);

        assertCompletionFails(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_VALUE);
        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testValueConfiguredDuringEnrollmentIsNotReplaced() throws Exception {

        userClaims.put(VALUE_CLAIM, OTHER_VALUE);
        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);

        assertCompletionFails(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ENROLLMENT_VALUE_ALREADY_CONFIGURED);
        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testFailureToSaveValueIsReportedWithoutInternalDetails() throws Exception {

        setPendingValue(VALUE);
        handler.recordOTPSent(context, VALUE);
        doThrow(new UserStoreClientException("Attribute value is not unique: internal detail"))
                .when(userStoreManager).setUserClaimValues(anyString(), anyMap(), isNull());

        assertCompletionFails(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_VALUE);

        // Only a fixed error key is shown to the user.
        assertEquals(context.getProperty(AUTHENTICATOR + EnrollmentConstants.ENROLLMENT_ERROR),
                "&authFailure=true&authFailureMsg=" + MESSAGE_PREFIX + ".enrollment.failed");
        assertNull(handler.getPendingValue(context));
        assertEquals(handler.events, Arrays.asList("skip", "clear"),
                "The verification skip must be cleared after a failure.");
    }

    @Test
    public void testNothingIsSavedWithoutPendingValue() throws Exception {

        handler.completeEnrollment(context, true);

        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testAppNativeAuthenticationRequestsValue() {

        setAwaitingValue();
        List<AuthenticatorParamMetadata> params = new ArrayList<>();
        List<String> requiredParams = new ArrayList<>();

        assertTrue(handler.addAuthInitiationParams(context, params, requiredParams));
        assertEquals(requiredParams, Collections.singletonList(VALUE_PARAM));
        assertEquals(params.get(0).getName(), VALUE_PARAM);
    }

    @Test
    public void testAppNativeAuthenticationIsUnchangedWhenValueIsNotRequested() {

        setPendingValue(VALUE);
        List<AuthenticatorParamMetadata> params = new ArrayList<>();
        List<String> requiredParams = new ArrayList<>();

        assertFalse(handler.addAuthInitiationParams(context, params, requiredParams));
        assertTrue(params.isEmpty());
        assertTrue(requiredParams.isEmpty());
    }

    @Test
    public void testEnrollmentStateIsKeptPerAuthenticator() {

        setPendingValue(VALUE);
        assertNull(new TestHandler("another-otp-authenticator").getPendingValue(context),
                "Enrollments of different authenticators in a flow must not interfere.");
    }

    @Test
    public void testApplicationCanOptOutThroughCommonScriptOptions() throws Exception {

        setRuntimeParam(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS,
                EnrollmentConstants.ENROL_USER_IN_AUTHENTICATION_FLOW, "false");

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testFailureToReadOrganizationSettingIsReported() throws Exception {

        when(governanceService.getConfiguration(any(String[].class), eq(TENANT_DOMAIN)))
                .thenThrow(new IdentityGovernanceException("error"));
        try {
            handler.handleInitiation(request, response, context);
            fail("Expected the configuration failure to be reported.");
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(),
                    "TEST-" + AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG.getCode());
        }
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentWhenOnlyAuthenticationFlowHandlersPreceded() throws Exception {

        // An authentication flow handler, such as identifier first, does not authenticate the user.
        AuthenticatorConfig flowHandlerConfig = new AuthenticatorConfig();
        flowHandlerConfig.setApplicationAuthenticator(mock(AuthenticationFlowHandler.class));
        AuthenticatedIdPData idPData = new AuthenticatedIdPData();
        idPData.setAuthenticators(Collections.singletonList(flowHandlerConfig));
        context.setCurrentAuthenticatedIdPs(Collections.singletonMap("LOCAL", idPData));

        assertFalse(handler.handleInitiation(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testOtpSubmissionOrResendIsNotAValueSubmission() {

        setAwaitingValue();
        when(request.getParameter(VALUE_PARAM)).thenReturn(VALUE);
        assertTrue(handler.isValueSubmission(request, context));

        when(request.getParameter(AuthenticatorConstants.CODE)).thenReturn("123456");
        assertFalse(handler.isValueSubmission(request, context));

        HttpServletRequest resendRequest = mock(HttpServletRequest.class);
        when(resendRequest.getParameter(VALUE_PARAM)).thenReturn(VALUE);
        when(resendRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");
        assertFalse(handler.isValueSubmission(resendRequest, context));
    }

    private void setRuntimeParam(String authenticatorName, String name, String value) {

        Map<String, Map<String, String>> runtimeParams = new HashMap<>();
        Map<String, String> params = new HashMap<>();
        params.put(name, value);
        runtimeParams.put(authenticatorName, params);
        context.addAuthenticatorParams(runtimeParams);
    }

    private void setAwaitingValue() {

        context.setProperty(AUTHENTICATOR + EnrollmentConstants.AWAITING_VALUE, true);
    }

    private void setPendingValue(String value) {

        context.setProperty(AUTHENTICATOR + EnrollmentConstants.PENDING_VALUE, value);
    }

    private void assertCompletionFails(AuthenticatorConstants.ErrorMessages expectedError) {

        try {
            handler.completeEnrollment(context, true);
            fail("Expected the enrollment to fail.");
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(), "TEST-" + expectedError.getCode());
        }
    }

    private String captureRedirectUrl() throws Exception {

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(response, atLeastOnce()).sendRedirect(urlCaptor.capture());
        return urlCaptor.getValue();
    }

    private static AuthenticatedUser buildLocalUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("alice");
        user.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain(TENANT_DOMAIN);
        user.setFederatedUser(false);
        return user;
    }

    private static AuthenticationContext buildContext(AuthenticatedUser user) {

        StepConfig firstStep = new StepConfig();
        firstStep.setSubjectAttributeStep(true);
        firstStep.setAuthenticatedUser(user);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, firstStep);
        stepMap.put(2, new StepConfig());
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(2);
        context.setCurrentAuthenticator(AUTHENTICATOR);
        return context;
    }

    /**
     * Handler of a test channel, which records when the verification on update is skipped and cleared.
     */
    private static class TestHandler extends AbstractOTPProgressiveEnrollmentHandler {

        private final List<String> events = new ArrayList<>();
        private int maxEnrollmentAttempts = EnrollmentConstants.DEFAULT_MAX_ENROLLMENT_ATTEMPTS;

        TestHandler(String authenticatorName) {

            super(authenticatorName, "TEST", "test-otp");
        }

        @Override
        protected String getValueClaimUri() {

            return VALUE_CLAIM;
        }

        @Override
        protected String getVerifiedClaimUri() {

            return VERIFIED_CLAIM;
        }

        @Override
        protected String getValueParameterName() {

            return VALUE_PARAM;
        }

        @Override
        protected String getValueParameterDisplayName() {

            return "Test Value";
        }

        @Override
        protected String getValueParameterI18nKey() {

            return "test.value.param";
        }

        @Override
        protected String getMessageKeyPrefix() {

            return MESSAGE_PREFIX;
        }

        @Override
        protected String getEnrollmentEnabledSettingKey() {

            return ENABLED_SETTING;
        }

        @Override
        protected String getValueRegexSettingKey() {

            return REGEX_SETTING;
        }

        @Override
        protected String getDefaultValueRegex() {

            return "^\\+?[0-9]{7,15}$";
        }

        @Override
        protected String getEnrollmentPageUrl() {

            return ENROLLMENT_PAGE;
        }

        @Override
        protected String getErrorPageUrl(AuthenticationContext context) {

            return ERROR_PAGE;
        }

        @Override
        protected int getMaxEnrollmentAttempts() {

            return maxEnrollmentAttempts;
        }

        @Override
        protected void invalidateOTP(AuthenticationContext context) {

            context.removeProperty(OTP);
        }

        @Override
        protected void skipVerificationOnUpdate() {

            events.add("skip");
        }

        @Override
        protected void clearVerificationSkip() {

            events.add("clear");
        }
    }
}
