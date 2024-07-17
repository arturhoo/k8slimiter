package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type RateLimit struct {
	Labels     map[string]string `yaml:"labels"`
	RatePerSec float32           `yaml:"ratePerSec"`
	Burst      int               `yaml:"burst"`
}

type RateLimitConfig struct {
	Rules        []RateLimit `yaml:"rules"`
	DefaultLimit RateLimit   `yaml:"defaultLimit"`
}

var (
	rateLimitConfig RateLimitConfig
	limiters        map[string]*rate.Limiter
)

func main() {
	loadRateLimitConfig()
	makeLimiters()

	http.HandleFunc("/validate", validatingHandler)
	http.HandleFunc("/healthz", healthzHandler)
	http.HandleFunc("/livez", livezHandler)

	startServer()
}

func loadRateLimitConfig() {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Error getting in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating clientset: %v", err)
	}

	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Fatalf("Error reading namespace: %v", err)
	}

	cms := clientset.CoreV1().ConfigMaps(string(namespace))
	cm, err := cms.Get(context.Background(), "k8slimiter-config", metav1.GetOptions{})
	if err != nil {
		log.Fatalf("Error getting ConfigMap: %v", err)
	}

	yamlConfig := cm.Data["config.yaml"]
	err = yaml.Unmarshal([]byte(yamlConfig), &rateLimitConfig)
	if err != nil {
		log.Fatalf("Error unmarshalling config: %v", err)
	}
}

func makeLimiters() {
	limiters = make(map[string]*rate.Limiter)

	if len(rateLimitConfig.DefaultLimit.Labels) > 0 {
		log.Fatalf("Error: labels set on default limit")
	}
	if rateLimitConfig.DefaultLimit.RatePerSec == 0 {
		log.Println("Not defining a defalut limiter")
	} else {
		limiters["default"] = rate.NewLimiter(
			rate.Limit(rateLimitConfig.DefaultLimit.RatePerSec),
			rateLimitConfig.DefaultLimit.Burst,
		)
	}

	for _, rule := range rateLimitConfig.Rules {
		key := generateKeyFromLabels(rule.Labels)
		limiter := rate.NewLimiter(rate.Limit(rule.RatePerSec), rule.Burst)
		limiters[key] = limiter
	}
}

func validatingHandler(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		http.Error(w, "Error parsing pod spec: "+err.Error(), http.StatusBadRequest)
		return
	}

	limiter, err := getLimiter(pod.Labels)
	var status, msg string
	status = metav1.StatusSuccess
	allowed := true

	if err == nil {
		log.Printf("Using a limiter\n")
		allowed = limiter.Allow()
		if !allowed {
			status = metav1.StatusFailure
			msg = "rate limit exceeded"
		}
	}

	review.Response = &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: allowed,
		Result: &metav1.Status{
			Status:  status,
			Message: msg,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		http.Error(w, "Error encoding response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	if err != nil {
		http.Error(w, "Error encoding response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func livezHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	if err != nil {
		http.Error(w, "Error encoding response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func getLimiter(podLabels map[string]string) (*rate.Limiter, error) {
	key := getLimiterKey(podLabels)
	if limiter, found := limiters[key]; found {
		return limiter, nil
	}
	return nil, fmt.Errorf("no limiter found for key %s", key)
}

func getLimiterKey(podLabels map[string]string) string {
	for _, rule := range rateLimitConfig.Rules {
		if labelsMatch(podLabels, rule.Labels) {
			return generateKeyFromLabels(rule.Labels)
		}
	}
	return "default"
}

func labelsMatch(podLabels, ruleLabels map[string]string) bool {
	for k, v := range ruleLabels {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func generateKeyFromLabels(labels map[string]string) string {
	keyParts := []string{}
	for k, v := range labels {
		keyParts = append(keyParts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(keyParts)
	return strings.Join(keyParts, ",")
}

func startServer() {
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
		log.Fatal(http.ListenAndServeTLS(addr, certPath, keyPath, nil))
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}
