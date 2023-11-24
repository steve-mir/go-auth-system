package mailer

import (
	"testing"

	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestSendEmailWithSMTP(t *testing.T) {
	config, err := utils.LoadConfig("..")
	require.NoError(t, err)

	sender := NewSMTPSender("Settle in", config.SMTPAddr, config.SMTPHost, config.SMTPUsername, config.SMTPPassword)

	subject := "A test email"
	content := `
	<h1> Welcome onboard </h1>
	<p>This is a test message from John Doe</>
	`
	to := []string{"ekestephen25@gmail.com"}
	attachFiles := []string{"../README.md"}

	err = sender.SendEmail(subject, content, to, nil, nil, attachFiles)
	require.NoError(t, err)
}
