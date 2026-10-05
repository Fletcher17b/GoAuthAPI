package ratelimiter

import (
	luascripts "AuthAPI/main/internal/auth/luascripts"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// nts: TODO: when we implement variable policies introduce ways to dynamically set limits and limit triggers
var ErrRateLimited = errors.New("too many requests")

type RedisClient struct {
	redis *redis.Client
}

type RateLimitState struct {
	Attempts int64 // Counter for attempts
	LastTry  int64 //Last attempt performed
	NextTry  int64 //earliest time another attempt is permitted
}

const (
	RateAllowed = iota
	RateLimited
	RateNotify
)

func RedisKeyBuilder(endpoint, ip, email string) []string {
	prefix := "auth:" + endpoint

	keys := make([]string, 0, 3)
	keys = append(keys,
		fmt.Sprintf("%s:ip:%s", prefix, ip),
		fmt.Sprintf("%s:account:%s", prefix, email),
		fmt.Sprintf("%s:pair:%s:%s", prefix, ip, email),
	)

	return keys
}

func NewRedisLimiter(redis *redis.Client) RedisLimiter {
	return &RedisClient{
		redis: redis,
	}
}

type RedisLimiter interface {
	CheckLogin(ctx context.Context, ip, email string) error
	RecordLoginFailure(ctx context.Context, ip, email string, notifyAttempt int64) (error, int)

	CheckSignup(ctx context.Context, ip string) error
	RecordSignupAttempt(ctx context.Context, ip string) error

	CheckPasswordResetRequest(ctx context.Context, ip, email string) error
	RecordPasswordResetRequest(ctx context.Context, ip, email string) error
}

// nts: TODO: would be useful to later on
func (l *RedisClient) CheckLogin(
	ctx context.Context,
	ip string,
	email string,
) error {

	keys := RedisKeyBuilder("login", ip, email)
	blocked, err := luascripts.CheckLoginScript.Run(
		ctx,
		l.redis,
		keys,
		time.Now().Unix(),
	).Int()

	if err != nil {
		return err
	}

	if blocked == 1 {
		return ErrRateLimited
	}

	return nil
}

func (l *RedisClient) RecordLoginFailure(
	ctx context.Context,
	ip string,
	email string,
	notifyAttempt int64,
) (error, int) {

	keys := RedisKeyBuilder("login", ip, email)
	result, err := luascripts.RecordLoginFailureScript.Run(
		ctx,
		l.redis,
		keys,
		time.Now().Unix(),
		notifyAttempt,
	).Int()

	if err != nil {
		return err, 0
	}

	return nil, result
}

func (l *RedisClient) CheckSignup(
	ctx context.Context,
	ip string,

) error {
	key := RedisKeyBuilder("signup", ip, "")

	result, err := luascripts.CheckSignupScript.Run(
		ctx,
		l.redis,
		[]string{key[0]},
		time.Now().Unix(),
	).Int()

	if err != nil {
		return err
	}

	if result == 1 {
		return ErrRateLimited
	}

	return nil
}

func (l *RedisClient) RecordSignupAttempt(
	ctx context.Context,
	ip string,
) error {
	key := RedisKeyBuilder("signup", ip, "")

	_, err := luascripts.RecordSignupFailureScript.Run(
		ctx,
		l.redis,
		[]string{key[0]},
		time.Now().Unix(),
	).Result()

	return err
}

func (l *RedisClient) CheckPasswordResetRequest(
	ctx context.Context,
	ip string,
	email string,
) error {
	keys := RedisKeyBuilder("reset", ip, email)[:2]

	result, err := luascripts.CheckResetRequestScript.Run(
		ctx,
		l.redis,
		keys,
		time.Now().Unix(),
	).Int()

	if err != nil {
		return err
	}

	if result == 1 {
		return ErrRateLimited
	}

	return nil
}

func (l *RedisClient) RecordPasswordResetRequest(
	ctx context.Context,
	ip string,
	email string,
) error {
	keys := RedisKeyBuilder("reset", ip, email)[:2]

	_, err := luascripts.RecordResetRequestFailureScript.Run(
		ctx,
		l.redis,
		keys,
		time.Now().Unix(),
	).Result()

	return err
}
