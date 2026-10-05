package luascripts

import (
	"embed"

	"github.com/redis/go-redis/v9"
)

//go:embed *.lua
var scripts embed.FS

var (
	CheckLoginScript         *redis.Script
	RecordLoginFailureScript *redis.Script

	CheckSignupScript         *redis.Script
	RecordSignupFailureScript *redis.Script

	CheckResetRequestScript         *redis.Script
	RecordResetRequestFailureScript *redis.Script
)

func Init() error {
	checkLogin, err := scripts.ReadFile("login_check.lua")
	if err != nil {
		return err
	}

	recordLogin, err := scripts.ReadFile("login_recordfailure.lua")
	if err != nil {
		return err
	}

	checkSignup, err := scripts.ReadFile("signup_check.lua")
	if err != nil {
		return err
	}

	recordSignup, err := scripts.ReadFile("signup_recordfailure.lua")
	if err != nil {
		return err
	}

	checkresetrequest, err := scripts.ReadFile("resetpasswordrequest_check.lua")
	if err != nil {
		return err
	}

	recordresetrequest, err := scripts.ReadFile("resetpasswordrequest_recordfailure.lua")
	if err != nil {
		return err
	}

	CheckLoginScript = redis.NewScript(string(checkLogin))
	RecordLoginFailureScript = redis.NewScript(string(recordLogin))

	CheckSignupScript = redis.NewScript(string(checkSignup))
	RecordSignupFailureScript = redis.NewScript(string(recordSignup))

	CheckResetRequestScript = redis.NewScript(string(checkresetrequest))
	RecordResetRequestFailureScript = redis.NewScript(string(recordresetrequest))

	return nil
}
