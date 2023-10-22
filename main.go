package main

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

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
			certPath = "./cert/localhost.pem"
		}
		if keyPath = os.Getenv("KEY_PATH"); keyPath == "" {
			keyPath = "./cert/localhost-key.pem"
		}
		r.RunTLS(addr, certPath, keyPath)
	} else {
		r.Run(addr)
	}
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
