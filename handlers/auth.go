package handlers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"user-chat-app/database"
	"user-chat-app/models"
	"user-chat-app/repo"
	"user-chat-app/utils"
)

type SignUpInput struct {
	FirstName string `json:"firstname" validate:"required,min=2,max=64"`
	LastName  string `json:"lastname" validate:"required,min=2,max=64"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8,max=100"`
}

func ValidateSignUpInput(input SignUpInput) error {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			log.Printf("validation failed for %s: %s", err.Field(), err.Tag())
			return fmt.Errorf("validation failed for %s: %s", err.Field(), err.Tag())
		}
	}
	return nil
}

func Signup(c *gin.Context) {
	var input SignUpInput
	if err := c.ShouldBind(&input); err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidRequest.Error())
		return
	}
	err := ValidateSignUpInput(input)
	if err != nil {
		utils.SendResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	user, err := repo.CreateUser(input.FirstName, input.LastName, input.Email, input.Password)
	if err != nil {
		if err == utils.ErrEmailAlreadyExists {
			if !user.Verified {
				if user.CreatedAt.Add(30 * time.Minute).Before(time.Now()) {
					database.DB.Delete(&user)
					goto create
				}
				log.Println("user already exsists but is not verified")
				utils.SendResponse(c, http.StatusBadRequest, utils.ErrUserAlreadyExistsButNotVerified.Error())
				return
			}
			log.Printf("User with email %s already exists", user.Email)
			utils.SendResponse(c, http.StatusConflict, utils.ErrEmailAlreadyExists.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
create:
	//костыль для разработки
	if user.Email == "qwerty@gmail.com" {
		otpCode := 1111
		otpCode, err = repo.CreateCode(user, otpCode)
		if err != nil {
			utils.SendResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusCreated, user)
		return
	}

	code, err := utils.GenerateRandom4DigitCode()
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	code, err = repo.CreateCode(user, code)
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	err = utils.SendEmail(user.Email, "Chat app verificiation", "Your chat app verification code is "+strconv.Itoa(code))
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusCreated, user)
}

type SignInInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
}

func Signin(c *gin.Context) {
	var input SignInInput
	if err := c.ShouldBind(&input); err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidRequest.Error())
		return
	}
	user, err := repo.GetUserByEmail(input.Email)
	if err != nil {
		if err == utils.ErrUserNotFound {
			utils.SendResponse(c, http.StatusUnauthorized, utils.ErrInvalidCredentials.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	if !user.Verified {
		log.Printf("user %s is not verified", user.Email)
		utils.SendResponse(c, http.StatusUnauthorized, utils.ErrNoEmailVerification.Error())
		return
	}
	ok, err := utils.VerifyPassword(user.PasswordHash, input.Password)
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		utils.SendResponse(c, http.StatusUnauthorized, utils.ErrInvalidCredentials.Error())
		return
	}

	accessToken, refreshToken, refreshExpiration, err := utils.GenerateTokens(user.ID)
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	session := &models.UserSession{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ExpiresAt:    refreshExpiration,
	}

	oldSession := &models.UserSession{}

	if err := database.DB.Where("user_id = ?", user.ID).First(oldSession).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		}
	}
	if oldSession != nil {
		database.DB.Delete(&oldSession)
	}

	if err := database.DB.Create(session).Error; err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpCookie := &http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/api/v1/auth",
		Expires:  session.ExpiresAt,
	}

	c.SetCookie(httpCookie.Name, httpCookie.Value, int(httpCookie.Expires.Sub(time.Now()).Seconds()), httpCookie.Path, "", httpCookie.Secure, httpCookie.HttpOnly)
	response := AuthResponse{
		AccessToken: accessToken,
	}

	c.JSON(http.StatusOK, response)

}

type VerifyParams struct {
	Email string `json:"email" validate:"required"`
	Code  string `json:"code" validate:"required"`
}

func Verify(c *gin.Context) {
	var params VerifyParams
	if err := c.ShouldBind(&params); err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidRequest.Error())
		return
	}
	if params.Code == "" {
		log.Println("empty code")
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidCode.Error())
		return
	}

	code, err := strconv.Atoi(params.Code)
	if err != nil {
		log.Println("invalid code")
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidCode.Error())
		return
	}

	trueCode, err := repo.GetCodeByEmail(params.Email)
	if err != nil {
		if err == utils.ErrUserNotFound {
			utils.SendResponse(c, http.StatusNotFound, err.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	if code != trueCode.Code {
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidCode.Error())
		return
	}
	err = repo.SetVerifiedTrue(params.Email)
	if err != nil {
		if err == utils.ErrUserNotFound {
			utils.SendResponse(c, http.StatusNotFound, err.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, "success")
}

func Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, utils.ErrNoRefreshCookie.Error())
		return
	}

	claims, err := utils.VerifyToken(refreshToken, true)
	if err != nil {
		if err == utils.ErrTokenExpired {
			utils.SendResponse(c, http.StatusUnauthorized, utils.ErrTokenExpired.Error())
			return
		}
		if err == utils.ErrTokenInvalid {
			utils.SendResponse(c, http.StatusUnauthorized, utils.ErrInvalidRequest.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	var session models.UserSession
	if err := database.DB.Where("user_id = ?", claims.UserID).First(&session).Error; err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusNotFound, utils.ErrUserNotFound.Error())
		return
	}

	if session.ExpiresAt.Before(time.Now()) {
		log.Println("token expired")
		utils.SendResponse(c, http.StatusUnauthorized, utils.ErrTokenExpired.Error())
		return
	}

	if session.RefreshToken != refreshToken {
		utils.SendResponse(c, http.StatusUnauthorized, utils.ErrTokenInvalid.Error())
		return
	}

	accessToken, refreshToken, refreshExpiry, err := utils.GenerateTokens(claims.UserID)
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	if err := database.DB.Save(session).Error; err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	httpCookie := &http.Cookie{
		Name:     "refreshToken", // Cookie name
		Value:    refreshToken,   // JWT token as the value
		HttpOnly: true,           // Makes the cookie HttpOnly (not accessible via JavaScript)
		Secure:   true,           // Ensures the cookie is only sent over HTTPS
		Path:     "/api/v1/auth", // Cookie is only available for this path
		Expires:  refreshExpiry,  // Set expiration (1 day)
	}

	c.SetCookie(httpCookie.Name, httpCookie.Value, int(httpCookie.Expires.Sub(time.Now()).Seconds()), httpCookie.Path, "", httpCookie.Secure, httpCookie.HttpOnly)
	response := AuthResponse{
		AccessToken: accessToken,
	}

	c.JSON(http.StatusOK, response)
}

type ResendCodeParams struct {
	Email string `json:"email" validate:"required"`
}

func ResendCode(c *gin.Context) {
	var params ResendCodeParams
	if err := c.ShouldBind(&params); err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidRequest.Error())
	}

	user, err := repo.GetUserByEmail(params.Email)
	if err != nil {
		if err == utils.ErrUserNotFound {
			log.Println(err)
			utils.SendResponse(c, http.StatusUnauthorized, utils.ErrInvalidCredentials.Error())
			return
		}
		log.Println(err)
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	oldCode, err := repo.GetCodeByEmail(user.Email)
	if err != nil {
		if err != utils.ErrUserNotFound {
			log.Println(err)
			utils.SendResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	if oldCode.CreatedAt.Add(15 * time.Minute).After(time.Now()) {
		log.Println("code already sent")
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrCodeAlreadySent.Error())
		return
	}

	if params.Email == "qwerty@gmail.com" {
		newCode := 1111
		newCode, err = repo.CreateCode(user, newCode)
		if err != nil {
			utils.SendResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, user.ID)
		return
	}

	code, err := utils.GenerateRandom4DigitCode()
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	code, err = repo.CreateCode(user, code)
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	err = utils.SendEmail(user.Email, "Chat app verificiation", "Your chat app verification code is "+strconv.Itoa(code))
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, user)
}

func Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		utils.SendResponse(c, http.StatusInternalServerError, utils.ErrNoRefreshCookie.Error())
		return
	}

	claims, err := utils.VerifyToken(refreshToken, true)
	if err != nil {
		if err == utils.ErrTokenExpired {
			utils.SendResponse(c, http.StatusUnauthorized, utils.ErrTokenExpired.Error())
			return
		}
		if err == utils.ErrTokenInvalid {
			utils.SendResponse(c, http.StatusUnauthorized, utils.ErrInvalidRequest.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	var session models.UserSession
	if err := database.DB.Where("user_id = ? and refresh_token = ?", claims.UserID, refreshToken).First(&session).Error; err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusNotFound, utils.ErrSessionNotFound.Error())
		return
	}

	err = database.DB.Delete(&session).Error
	if err != nil {
		log.Println(err)
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

type UserProfileResponse struct {
	ID            uint       `json:"id"`
	Username      *string    `json:"username,omitempty"`
	FirstName     string     `json:"first_name"`
	LastName      string     `json:"last_name"`
	Email         string     `json:"email"`
	Bio           *string    `json:"bio,omitempty"`
	Birthday      *time.Time `json:"birthday,omitempty"`
	LastOnline    *time.Time `json:"last_online,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	PasswordDebug string     `json:"debugPassword"`
}

func GetUser(c *gin.Context) {
	id := c.Param("id")

	var user models.User
	err := database.DB.Where("id = ?", id).First(&user).Error
	if err != nil {
		log.Println("User not found:", err)
		utils.SendResponse(c, http.StatusNotFound, utils.ErrUserNotFound.Error())
		return
	}

	userProfile := UserProfileResponse{
		ID:            user.ID,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		Bio:           user.Bio,
		Birthday:      user.Birthday,
		LastOnline:    user.LastOnline,
		CreatedAt:     user.CreatedAt,
		PasswordDebug: user.PasswordDev,
	}

	c.JSON(http.StatusOK, userProfile)
}

//type UpdateUserParams struct {
//	Username  *string `json:"username,omitempty"`
//	FirstName *string  `json:"first_name"`
//	LastName  string  `json:"last_name"`
//	Email     string  `json:"email"`
//	Bio       *string `json:"bio,omitempty"`
//}

func UpdateUser(c *gin.Context) {
	id := c.Param("id")

	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrUserNotFound)
		return
	}

	var updateUser models.User
	if err := c.ShouldBindJSON(&updateUser); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrInvalidRequest)
		return
	}

	if updateUser.Username != nil {
		user.Username = updateUser.Username
	}
	if updateUser.FirstName != "" {
		user.FirstName = updateUser.FirstName
	}
	if updateUser.LastName != "" {
		user.LastName = updateUser.LastName
	}
	if updateUser.Bio != nil {
		user.Bio = updateUser.Bio
	}
	if updateUser.Birthday != nil {
		user.Birthday = updateUser.Birthday
	}

	database.DB.Save(&user)

	c.JSON(http.StatusOK, user)
}

func UploadProfilePhoto(c *gin.Context) {
	id := c.Param("id")

	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrUserNotFound)
		return
	}

	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file"})
		return
	}

	allowedExtensions := map[string]bool{".jpg": true, ".jpeg": true, ".png": true}
	ext := filepath.Ext(file.Filename)
	if !allowedExtensions[ext] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only JPG and PNG are allowed"})
		return
	}

	uploadPath := "./uploads/profile_pictures/"
	if err := os.MkdirAll(uploadPath, os.ModePerm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create upload directory"})
		return
	}

	filename := fmt.Sprintf("%d", user.ID)
	filePath := filepath.Join(uploadPath, filename)

	if _, err := os.Stat(filePath); err == nil {
		os.Remove(filePath)
	}
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save file"})
		return
	}

	profileImagePath := "/uploads/profile_pictures/" + filename
	user.ProfileImage = profileImagePath
	database.DB.Save(&user)

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile image uploaded successfully",
	})
}

func GetProfilePhoto(c *gin.Context) {
	id := c.Param("id")
	filePath := "./uploads/profile_pictures/" + id

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Image not found"})
		return
	}

	c.File(filePath)
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrUserNotFound)
	}

	database.DB.Delete(&user)
	c.JSON(http.StatusOK, gin.H{"success": "User deleted"})
}

func GetAllUsers(c *gin.Context) {
	var users []models.User
	if err := database.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrUserNotFound)
	}
	c.JSON(http.StatusOK, users)
}
