package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RateLimit struct {
	Labels     map[string]string `yaml:"labels"`
	Kinds      []string          `yaml:"kinds"`
	RatePerSec float32           `yaml:"ratePerSec"`
	Burst      int               `yaml:"burst"`
	Limiter    *rate.Limiter     `yaml:"-"`
}

type RateLimitConfig struct {
	Rules        []RateLimit `yaml:"rules"`
	DefaultLimit RateLimit   `yaml:"defaultLimit"`
}

var (
	rateLimitConfig RateLimitConfig
	knownKinds      = []string{"Pod", "Deployment", "StatefulSet"}
)

func LoadRateLimitConfig() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		log.Fatal("CONFIG_PATH environment variable is not set")
	}

	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	err = yaml.Unmarshal(yamlFile, &rateLimitConfig)
	if err != nil {
		log.Fatalf("Error unmarshalling config: %v", err)
	}
}

func CreateLimiters() {
	if len(rateLimitConfig.DefaultLimit.Labels) > 0 {
		log.Fatalf("Error: labels set on default limit")
	}
	for _, kind := range rateLimitConfig.DefaultLimit.Kinds {
		if !slices.Contains(knownKinds, kind) {
			log.Fatalf("Error: unknown kind %s in default limit", kind)
		}
	}
	if rateLimitConfig.DefaultLimit.RatePerSec == 0 ||
		rateLimitConfig.DefaultLimit.Burst == 0 ||
		len(rateLimitConfig.DefaultLimit.Kinds) == 0 {
		log.Println("Not defining a default limiter")
	} else {
		rateLimitConfig.DefaultLimit.Limiter = rate.NewLimiter(
			rate.Limit(rateLimitConfig.DefaultLimit.RatePerSec),
			rateLimitConfig.DefaultLimit.Burst,
		)
		log.Printf("created default limiter")
	}

	for i := range rateLimitConfig.Rules {
		rule := &rateLimitConfig.Rules[i]
		for _, kind := range rule.Kinds {
			if !slices.Contains(knownKinds, kind) {
				log.Fatalf("Error: unknown kind %s in rule", kind)
			}
		}
		if rule.Burst == 0 {
			log.Println("Found burst of 0, setting to 1")
			rule.Burst = 1
		}
		rule.Limiter = rate.NewLimiter(rate.Limit(rule.RatePerSec), rule.Burst)
		log.Printf("created limiter for rule %d", i)
	}
}

func ValidatingHandler(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var labels map[string]string
	var err error
	var name string
	kind := review.Request.Kind.Kind

	switch kind {
	case "Pod":
		var pod corev1.Pod
		if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
			http.Error(w, "Error parsing pod spec: "+err.Error(), http.StatusBadRequest)
			return
		}
		name = pod.Name
		labels = pod.Labels
	case "Deployment":
		var deployment appsv1.Deployment
		if err := json.Unmarshal(review.Request.Object.Raw, &deployment); err != nil {
			http.Error(w, "Error parsing deployment spec: "+err.Error(), http.StatusBadRequest)
			return
		}
		name = deployment.Name
		labels = deployment.Spec.Template.Labels
	case "StatefulSet":
		var statefulSet appsv1.StatefulSet
		if err := json.Unmarshal(review.Request.Object.Raw, &statefulSet); err != nil {
			http.Error(w, "Error parsing statefulset spec: "+err.Error(), http.StatusBadRequest)
			return
		}
		name = statefulSet.Name
		labels = statefulSet.Spec.Template.Labels
	default:
		http.Error(w, "Unsupported resource type", http.StatusBadRequest)
		return
	}

	limiter, err := getLimiter(kind, labels)
	var status, msg string
	status = metav1.StatusSuccess
	allowed := true

	if err == nil {
		allowed = limiter.Allow()
		log.Printf("resource kind=%s name=%s being ratelimited: %t", kind, name, !allowed)
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

func getLimiter(kind string, labels map[string]string) (*rate.Limiter, error) {
	for _, rule := range rateLimitConfig.Rules {
		if labelsMatchAndKindInList(labels, rule.Labels, kind, rule.Kinds) {
			return rule.Limiter, nil
		}
	}
	if labelsMatchAndKindInList(labels, rateLimitConfig.DefaultLimit.Labels, kind, rateLimitConfig.DefaultLimit.Kinds) {
		return rateLimitConfig.DefaultLimit.Limiter, nil
	}
	return nil, fmt.Errorf("no limiter found for kind %s and labels %v", kind, labels)
}

func labelsMatchAndKindInList(labels, ruleLabels map[string]string, kind string, ruleKinds []string) bool {
	if !slices.Contains(ruleKinds, kind) {
		return false
	}
	for k, v := range ruleLabels {
		if labels[k] != v {
			return false
		}
	}
	return true
}
