package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	swagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
	"io/ioutil"
	"log"
	"user-chat-app/database"
	_ "user-chat-app/docs"
	"user-chat-app/handlers"
	"user-chat-app/middleware"
	"user-chat-app/models"
)

// @title User Chat App API
// @version 1.0
// @host localhost:8080
// @BasePath /api/v1
func main() {

	database.InitDB()
	var tables []string
	if err := database.DB.Raw("SHOW TABLES").Scan(&tables).Error; err != nil {
		fmt.Errorf("failed to get tables: %w", err)
	}

	// Drop each table
	for _, table := range tables {
		if err := database.DB.Migrator().DropTable(table); err != nil {
			fmt.Errorf("failed to drop table %s: %w", table, err)
		}
	}
	// Auto-migrate tables
	err := database.DB.AutoMigrate(&models.User{}, &models.VerifyCode{}, &models.UserSession{})
	if err != nil {
		log.Fatal("Migration failed:", err)
	}

	sqlFile := "sql/seed_users.sql"
	sqlContent, err := ioutil.ReadFile(sqlFile)
	if err != nil {
		log.Fatalf("Error reading SQL seed file: %v", err)
	}

	// Run the SQL commands in the script
	err = executeSQLScript(string(sqlContent), database.DB)
	if err != nil {
		log.Fatalf("Error executing SQL seed script: %v", err)
	}

	router := gin.Default()
	router.GET("/swagger/*any", swagger.WrapHandler(swaggerFiles.Handler))

	apiV1 := router.Group("/api/v1")
	{
		auth := apiV1.Group("/auth")
		{
			auth.POST("/signup", handlers.Signup)
			auth.POST("/verify", handlers.Verify)
			auth.POST("/signin", handlers.Signin)
			auth.POST("/refresh", handlers.Refresh)
		}
		user := apiV1.Group("/user")
		user.Use(middleware.JWTAuthMiddleware()) // Apply JWT middleware to protect routes
		{
			user.GET("/profile", handlers.GetUserProfile) // Fetch user profile
			//user.PUT("/profile", handlers.UpdateUserProfile) // Update user profile
		}
	}

	router.Run(":8080")
}

func executeSQLScript(script string, db *gorm.DB) error {
	// Execute the raw SQL script
	if err := db.Exec(script).Error; err != nil {
		return fmt.Errorf("failed to execute SQL script: %w", err)
	}
	return nil
}
