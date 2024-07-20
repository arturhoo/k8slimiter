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

func TestCreateLimiters(t *testing.T) {
	rateLimitConfig = RateLimitConfig{
		Rules: []RateLimit{
			{
				Labels:     map[string]string{"app": "test"},
				Kinds:      []string{"Pod"},
				RatePerSec: 1,
				Burst:      5,
			},
		},
		DefaultLimit: RateLimit{
			Kinds:      []string{"Pod", "Deployment"},
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
				Labels:     map[string]string{"app": "test"},
				Kinds:      []string{"Pod"},
				RatePerSec: 1,
				Burst:      5,
			},
		},
		DefaultLimit: RateLimit{
			Kinds:      []string{"Pod", "Deployment"},
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
			kind:            "Pod",
			labels:          map[string]string{"app": "test"},
			expectedError:   false,
			expectedLimiter: rateLimitConfig.Rules[0].Limiter,
		},
		{
			name:            "Default limit",
			kind:            "Deployment",
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
			Kinds:      []string{"Pod"},
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
			Containers: []corev1.Container{{Name: "test", Image: "test"}},
		},
	}
	rawPod, _ := json.Marshal(pod)
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			Kind:   metav1.GroupVersionKind{Kind: "Pod"},
			Object: runtime.RawExtension{Raw: rawPod},
		},
	}
	body, _ := json.Marshal(review)

	// First request should be allowed
	req := httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var response admissionv1.AdmissionReview
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Response.Allowed)

	// Without sleeping, try to create another pod and ensure it is denied
	req = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response.Response.Allowed)

	// Sleep for 120ms, try to create another pod and ensure it is allowed
	time.Sleep(120 * time.Millisecond)
	req = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Response.Allowed)
}
