package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/time/rate"

	"github.com/gin-gonic/gin"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	r := gin.Default()

	r.POST("/validate", validatingHandler)
	r.GET("/healthz", healthzHandler)
	r.GET("/livez", livezHandler)

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	tlsEnabled := os.Getenv("TLS_ENABLED")
	if port == "" {
		if tlsEnabled == "true" {
			port = "8443"
		} else {
			port = "8080"
		}
	}
	addr := fmt.Sprintf("%s:%s", host, port)

	if tlsEnabled == "true" {
		var certPath, keyPath string
		if certPath = os.Getenv("CERT_PATH"); certPath == "" {
			certPath = "./certs/tls.crt"
		}
		if keyPath = os.Getenv("KEY_PATH"); keyPath == "" {
			keyPath = "./certs/tls.key"
		}
		r.RunTLS(addr, certPath, keyPath)
	} else {
		r.Run(addr)
	}
}

var limiter = rate.NewLimiter(rate.Every(10*time.Second), 1)

func validatingHandler(c *gin.Context) {
	var review admissionv1.AdmissionReview
	if err := c.Bind(&review); err != nil {
		return
	}

	allowed := limiter.Allow()
	var status, msg string
	if allowed {
		status = metav1.StatusSuccess
	} else {
		status = metav1.StatusFailure
		msg = "rate limit exceeded"
	}

	review.Response = &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: allowed,
		Result: &metav1.Status{
			Status:  status,
			Message: msg,
		},
	}
	c.JSON(200, review)
}

func healthzHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}

func livezHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}
