package handlers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"log"
	"net/http"
	"strconv"
	"time"
	"user-chat-app/database"
	"user-chat-app/models"
	"user-chat-app/repo"
	"user-chat-app/utils"
)

// SignUpInput represents the required fields for a signup request
// @Description Input structure for user signup
// @Param firstname body string true "First Name" example("John")
// @Param lastname body string true "Last Name" example("Doe")
// @Param email body string true "Email" example("john.doe@example.com")
// @Param password body string true "Password" example("password123")
// @Success 200 {string} string "User created successfully"
// @Failure 400 {object} utils.Response "Invalid request"
// @Router /signup [post]
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

// SignUpResponse is the response structure containing the user id of the signed up user
// @Description Response structure for userId
// @Success 200 {object} SignUpResponse "User id response"
type SignUpResponse struct {
	UserId int `json:"user_id"`
}

// Signup handles user registration and sends a verification code to the user's email.
// @Summary User Signup
// @Description Registers a new user by accepting a SignupInput JSON with first name, last name, email, and password. If successful, a verification code is sent to the user's email for confirmation.
// @Tags Auth
// @Accept json
// @Produce json
// @Param signupInput body SignUpInput true "User Signup Input" example({ "firstname": "John", "lastname": "Doe", "email": "john.doe@example.com", "password": "password123" })
// @Success 201 {object} SignUpResponse "User created successfully with a verification code sent to the email"
// @Failure 400 {object} utils.Response "Invalid request due to incorrect or missing parameters"
// @Failure 409 {object} utils.Response "Email already exists"
// @Failure 500 {object} utils.Response "Internal server error while creating user or sending verification code"
// @Router /auth/signup [post]
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
			log.Printf("User with email %s already exists", user.Email)
			utils.SendResponse(c, http.StatusConflict, utils.ErrEmailAlreadyExists.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
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

	c.JSON(http.StatusCreated, user.ID)
}

// SignInInput represents the required fields for a sign-in request
// @Description Input structure for user login
// @Param email body string true "Email" example("john.doe@example.com")
// @Param password body string true "Password" example("password123")
// @Success 200 {object} AuthResponse "Login successful"
// @Failure 400 {object} utils.Response "Invalid request"
// @Failure 404 {object} utils.Response "User not found"
// @Failure 401 {object} utils.Response "Invalid credentials"
// @Router /signin [post]
type SignInInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

// AuthResponse is the response structure containing authentication tokens
// @Description Response structure for access token
// @Success 200 {object} AuthResponse "Access token response"
type AuthResponse struct {
	AccessToken string `json:"access_token"`
}

// Signin handles user login and returns an access token and a refresh token upon successful authentication.
// @Summary User Signin
// @Description Logs in a user by accepting a SignInInput JSON with the user's email and password. If the credentials are correct and the email is verified, an access token and a refresh token are returned for subsequent authentication requests.
// @Tags Auth
// @Accept json
// @Produce json
// @Param signinInput body SignInInput true "User Signin Input" example({ "email": "john.doe@example.com", "password": "password123" })
// @Success 200 {object} AuthResponse "Login successful with access token and refresh token"
// @Failure 400 {object} utils.Response "Invalid request due to incorrect or missing parameters"
// @Failure 401 {object} utils.Response "Invalid credentials or email not verified"
// @Failure 404 {object} utils.Response "User not found"
// @Failure 500 {object} utils.Response "Internal server error while verifying user or generating tokens"
// @Router /auth/signin [post]
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
			utils.SendResponse(c, http.StatusNotFound, utils.ErrUserNotFound.Error())
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

// VerifyParams represents the required fields for verification
// @Description Input structure for verification
// @Param user_id body string true "User ID" example("123")
// @Param code body string true "Verification Code" example("1234")
// @Success 200 {string} string "Verification success"
// @Failure 400 {object} utils.Response "Invalid code or request"
// @Failure 404 {object} utils.Response "User not found"
// @Router /verify [post]
type VerifyParams struct {
	UserId string `json:"user_id" validate:"required"`
	Code   string `json:"code" validate:"required"`
}

// Verify handles the email verification process. The user provides their user ID and the verification code to confirm their email.
// @Summary User Email Verification
// @Description Verifies the user's email using the provided user ID and verification code. If the code matches, the user's email is marked as verified and they can access restricted areas.
// @Tags Auth
// @Accept json
// @Produce json
// @Param verifyParams body VerifyParams true "User Email Verification Input" example({ "user_id": "123", "code": "1234" })
// @Success 200 {string} string "Verification success"
// @Failure 400 {object} utils.Response "Invalid request due to empty or invalid code"
// @Failure 404 {object} utils.Response "User not found"
// @Failure 500 {object} utils.Response "Internal server error while verifying code or updating user status"
// @Router /auth/verify [post]
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
	userId, err := strconv.Atoi(params.UserId)
	if err != nil {
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidRequest.Error())
		return
	}
	trueCode, err := repo.GetCodeByUserId(userId)
	if err != nil {
		if err == utils.ErrUserNotFound {
			utils.SendResponse(c, http.StatusNotFound, err.Error())
			return
		}
		utils.SendResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	if code != trueCode {
		utils.SendResponse(c, http.StatusBadRequest, utils.ErrInvalidCode.Error())
		return
	}
	err = repo.SetVerifiedTrue(userId)
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

// Refresh handles the refresh of an access token using the refresh token stored in cookies. If the token is valid, a new access token and refresh token are issued for further use.
// @Summary Refresh Authentication Token
// @Description Refreshes the user's access token by verifying the refresh token from the user's cookies. If the token is valid, a new access token and refresh token are issued to continue the user's session.
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} AuthResponse "Tokens refreshed successfully with a new access token"
// @Failure 400 {object} utils.Response "Invalid refresh token or missing refresh token in cookies"
// @Failure 401 {object} utils.Response "Invalid or expired refresh token"
// @Failure 404 {object} utils.Response "User session not found"
// @Failure 500 {object} utils.Response "Internal server error while refreshing token or verifying refresh token"
// @Router /auth/refresh [post]
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

type UserProfileResponse struct {
	ID         uint       `json:"id"`
	Username   *string    `json:"username,omitempty"`
	FirstName  string     `json:"first_name"`
	LastName   string     `json:"last_name"`
	Email      string     `json:"email"`
	Bio        *string    `json:"bio,omitempty"`
	LastOnline *time.Time `json:"last_online,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// GetUserProfile retrieves the user's profile using the user ID from the access token.
// @Summary Get User Profile
// @Description Fetches the user's profile information using the ID extracted from the JWT access token.
// @Tags User
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} UserProfileResponse "User profile retrieved successfully"
// @Failure 401 {object} utils.Response "Unauthorized - Invalid or missing token"
// @Failure 404 {object} utils.Response "User not found"
// @Failure 500 {object} utils.Response "Internal server error"
// @Router /user/profile [get]
func GetUserProfile(c *gin.Context) {
	claims, exists := c.Get("userClaims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userClaims, ok := claims.(*utils.CustomClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user claims"})
		return
	}

	var user models.User
	err := database.DB.Where("id = ?", userClaims.UserID).First(&user).Error
	if err != nil {
		log.Println("User not found:", err)
		utils.SendResponse(c, http.StatusNotFound, utils.ErrUserNotFound.Error())
		return
	}

	// Construct the UserProfileResponse
	userProfile := UserProfileResponse{
		ID:         user.ID,
		Username:   user.Username,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		Email:      user.Email,
		Bio:        user.Bio,
		LastOnline: user.LastOnline,
		CreatedAt:  user.CreatedAt,
	}

	// Return the user profile response as JSON
	c.JSON(http.StatusOK, userProfile)
}
