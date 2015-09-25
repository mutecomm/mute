package smtpclient

import "testing"

func TestNew(t *testing.T) {
	mc := &MailClient{
		Port: 25,
	}
	err := mc.SendMail("test@cryptogroup.net", "test@cryptogroup.net", []byte("Ignore this"))
	if err == nil {
		t.Error("Remote server must deny this")
	}
	if err != ErrFinal {
		t.Errorf("Final error expected. Instead: %s", err)
	}
	if mc.LastErrorCode != 550 {
		t.Errorf("Expected 550 error. Instead: %s", mc.LastError)
	}
}

func TestLocal(t *testing.T) {
	// mc := MailClient{
	// 	Port:      2025,
	// 	SmartHost: "127.0.0.1",
	// 	NoSSL:     true,
	// }
	// err := mc.SendMail("mix-001@mute.berlin", "test@cryptogroup.net", []byte("message"))
	// if err != nil {
	// 	t.Errorf("Sendmail: %s %s", err, mc.LastError)
	// }
	// if err == nil {
	// 	t.Fatal("No error")
	// }
}
