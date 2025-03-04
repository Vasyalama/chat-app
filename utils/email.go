package utils

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
)

func SendEmail(to, subject, body string) error {

	from := os.Getenv("SMTP_EMAIL_FROM")
	password := os.Getenv("SMTP_PASSWORD")

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	message := []byte(fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body))

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, message)
	if err != nil {
		log.Printf("smtp error: %s", err)
		return ErrInternalServer
	}

	return nil
}
