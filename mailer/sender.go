package mailer

import (
	"fmt"
	"net/smtp"

	"github.com/jordan-wright/email"
)

type EmailSender interface {
	SendEmail(
		subject string,
		content string,
		to []string,
		cc []string,
		bcc []string,
		attachFiles []string,
	) error
}

type SMTPSender struct {
	name     string
	address  string
	host     string
	username string
	password string
}

func NewSMTPSender(name string, address string, host string, username string, password string) *SMTPSender {
	return &SMTPSender{
		name:     name,
		address:  address,
		host:     host,
		username: username,
		password: password,
	}
}

func (sender *SMTPSender) SendEmail(
	subject string,
	content string,
	to []string,
	cc []string,
	bcc []string,
	attachFiles []string,
) error {
	e := email.NewEmail()
	e.From = fmt.Sprintf("%s <%s>", sender.name, sender.username)
	e.Subject = subject
	e.HTML = []byte(content)
	e.To = to
	e.Cc = cc
	e.Bcc = bcc

	for _, f := range attachFiles {
		_, err := e.AttachFile(f)
		if err != nil {
			return fmt.Errorf("failed to attache file %s: %w", f, err)
		}
	}

	smtpAuth := smtp.PlainAuth("", sender.username, sender.password, sender.host)
	return e.Send(sender.address, smtpAuth)
}
