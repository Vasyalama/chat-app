package models

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	ID           uint       `gorm:"primaryKey;autoIncrement;not null"`
	Username     *string    `gorm:"size:64;unique;default:null"`
	FirstName    string     `gorm:"size:64;not null"`
	LastName     string     `gorm:"size:64;not null"`
	Email        string     `gorm:"size:255;unique;not null"`
	PasswordHash string     `gorm:"not null" json:"-"`
	Bio          *string    `gorm:"type:text"`
	Birthday     *time.Time `gorm:"type:datetime"`
	LastOnline   *time.Time `gorm:"default:null"`
	Verified     bool       `gorm:"not null;default:false"`
	CreatedAt    time.Time  `gorm:"autoCreateTime"`
	PasswordDev  string     `gorm:"size:255;default:null"`
	ProfileImage string     `gorm:"size:255;default:null"`
}

func (u *User) BeforeSave(tx *gorm.DB) (err error) {
	if u.Username != nil && *u.Username == "" {
		u.Username = nil
	}
	return nil
}

type UserSession struct {
	ID           uint      `gorm:"primaryKey;autoIncrement;not null"`
	UserID       uint      `gorm:"not null;index"`
	RefreshToken string    `gorm:"type:text;not null"`
	ExpiresAt    time.Time `gorm:"not null"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
}

func (UserSession) TableName() string {
	return "userSessions"
}

type VerifyCode struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;not null"`
	UserID    uint      `gorm:"not null;index"`
	Code      int       `gorm:"not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (VerifyCode) TableName() string {
	return "verifyCodes"
}
