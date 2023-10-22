package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/healthz", healthzHandler)
	r.GET("/livez", livezHandler)

	var certPath, keyPath string
	if certPath = os.Getenv("CERT_PATH"); certPath == "" {
		certPath = "./cert/localhost.pem"
	}
	if keyPath = os.Getenv("KEY_PATH"); keyPath == "" {
		keyPath = "./cert/localhost-key.pem"
	}

	r.RunTLS("localhost:8443", certPath, keyPath)
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
