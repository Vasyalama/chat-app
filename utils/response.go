package utils

import (
	"github.com/gin-gonic/gin"
)

// @description Response structure for messages
// @tags Response
// @type response
// @property message string The response message
type Response struct {
	Message string `json:"message"`
}

func SendResponse(c *gin.Context, statusCode int, message string) {
	c.AbortWithStatusJSON(statusCode, Response{message})
}
