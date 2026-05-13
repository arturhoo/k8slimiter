package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	appLabel     = "app"
	testName     = "test"
	validatePath = "/validate"
)

func TestCreateLimiters(t *testing.T) {
	rateLimitConfig = RateLimitConfig{
		Rules: []RateLimit{
			{
				Labels:     map[string]string{appLabel: testName},
				Kinds:      []string{kindPod},
				RatePerSec: 1,
				Burst:      5,
			},
		},
		DefaultLimit: RateLimit{
			Kinds:      []string{kindPod, kindDeployment},
			RatePerSec: 0.5,
			Burst:      3,
		},
	}
	CreateLimiters()

	assert.NotNil(t, rateLimitConfig.Rules[0].Limiter)
	assert.NotNil(t, rateLimitConfig.DefaultLimit.Limiter)
}

func TestGetLimiter(t *testing.T) {
	rateLimitConfig = RateLimitConfig{
		Rules: []RateLimit{
			{
				Labels:     map[string]string{appLabel: testName},
				Kinds:      []string{kindPod},
				RatePerSec: 1,
				Burst:      5,
			},
		},
		DefaultLimit: RateLimit{
			Kinds:      []string{kindPod, kindDeployment},
			RatePerSec: 0.5,
			Burst:      3,
		},
	}
	CreateLimiters()

	testCases := []struct {
		name            string
		kind            string
		labels          map[string]string
		expectedError   bool
		expectedLimiter *rate.Limiter
	}{
		{
			name:            "Matching rule",
			kind:            kindPod,
			labels:          map[string]string{appLabel: testName},
			expectedError:   false,
			expectedLimiter: rateLimitConfig.Rules[0].Limiter,
		},
		{
			name:            "Default limit",
			kind:            kindDeployment,
			labels:          map[string]string{},
			expectedError:   false,
			expectedLimiter: rateLimitConfig.DefaultLimit.Limiter,
		},
		{
			name:          "No matching limiter",
			kind:          "Service",
			labels:        map[string]string{},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			limiter, err := getLimiter(tc.kind, tc.labels)
			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, limiter)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedLimiter, limiter)
			}
		})
	}
}

func TestValidatingHandler(t *testing.T) {
	rateLimitConfig = RateLimitConfig{
		DefaultLimit: RateLimit{
			Kinds:      []string{kindPod},
			RatePerSec: 10,
			Burst:      1,
		},
	}
	CreateLimiters()
	handler := http.HandlerFunc(ValidatingHandler)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pod-1",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: testName, Image: testName}},
		},
	}
	rawPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod: %v", err)
	}
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			Kind:   metav1.GroupVersionKind{Kind: kindPod},
			Object: runtime.RawExtension{Raw: rawPod},
		},
	}
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("Failed to marshal review: %v", err)
	}

	// First request should be allowed
	req := httptest.NewRequest(http.MethodPost, validatePath, bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var response admissionv1.AdmissionReview
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Response.Allowed)

	// Without sleeping, try to create another pod and ensure it is denied
	req = httptest.NewRequest(http.MethodPost, validatePath, bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response.Response.Allowed)

	// Sleep for 120ms, try to create another pod and ensure it is allowed
	time.Sleep(120 * time.Millisecond)
	req = httptest.NewRequest(http.MethodPost, validatePath, bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Response.Allowed)
}
