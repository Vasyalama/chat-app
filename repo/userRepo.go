package repo

import (
	"gorm.io/gorm"
	"log"
	"user-chat-app/database"
	"user-chat-app/models"
	"user-chat-app/utils"
)

func CreateUser(firstName, lastName, email, password string) (*models.User, error) {
	hashedPassword, err := utils.HashPasswordWithSalt("", password, true)
	if err != nil {
		log.Println(err)
		return nil, utils.ErrInternalServer
	}

	user := models.User{
		FirstName:    firstName,
		LastName:     lastName,
		Email:        email,
		PasswordHash: hashedPassword,
	}

	err = database.DB.Where("email = ?", user.Email).First(&user).Error
	if err == nil {
		log.Printf("User with email %s already exists", user.Email)
		return nil, utils.ErrEmailAlreadyExists
	} else if err != gorm.ErrRecordNotFound {
		log.Println(err)
		return nil, utils.ErrInternalServer
	}

	err = database.DB.Create(&user).Error
	if err != nil {
		log.Println(err)
		return nil, utils.ErrInternalServer
	}

	return &user, nil
}

func CreateCode(user *models.User, code int) (int, error) {
	verifyCode := models.VerifyCode{
		UserID: user.ID,
		Code:   code,
	}
	err := database.DB.Create(&verifyCode).Error
	if err != nil {
		log.Println(err)
		return -1, utils.ErrInternalServer
	}
	return code, err
}

func GetCodeByUserId(id int) (int, error) {
	var verifyCode models.VerifyCode
	if err := database.DB.Where("user_id = ?", id).Order("created_at desc").First(&verifyCode).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			log.Println(err)
			return -1, utils.ErrUserNotFound
		}
		log.Println(err)
		return -1, utils.ErrInternalServer
	}
	return verifyCode.Code, nil
}

func SetVerifiedTrue(userId int) error {
	var user models.User

	if err := database.DB.First(&user, userId).Error; err != nil {
		if gorm.ErrRecordNotFound == err {
			log.Println(err)
			return utils.ErrUserNotFound
		}
		log.Println(err)
		return utils.ErrInternalServer
	}

	user.Verified = true

	if err := database.DB.Save(&user).Error; err != nil {
		log.Println(err)
		return utils.ErrInternalServer
	}

	return nil
}

func GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		if gorm.ErrRecordNotFound == err {
			log.Println(err)
			return nil, utils.ErrUserNotFound
		}
		log.Println(err)
		return nil, utils.ErrInternalServer
	}
	return &user, nil
}
