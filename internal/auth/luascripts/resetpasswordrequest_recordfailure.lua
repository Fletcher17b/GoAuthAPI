local now = tonumber(ARGV[1])

-- IP
local ip_window = redis.call("HGET", KEYS[1], "window_start")

if not ip_window or now - tonumber(ip_window) >= 60 then
    redis.call("HSET",
        KEYS[1],
        "attempts", 1,
        "window_start", now,
        "last_try", now,
        "next_try", now + 300
    )
else
    redis.call("HINCRBY", KEYS[1], "attempts", 1)
    redis.call("HSET",
        KEYS[1],
        "last_try", now,
        "next_try", now + 300
    )
end

redis.call("EXPIRE", KEYS[1], 3600)

-- Account
local account_window = redis.call("HGET", KEYS[2], "window_start")

if not account_window or now - tonumber(account_window) >= 3600 then
    redis.call("HSET",
        KEYS[2],
        "attempts", 1,
        "window_start", now,
        "last_try", now,
        "next_try", now + 300
    )
else
    redis.call("HINCRBY", KEYS[2], "attempts", 1)
    redis.call("HSET",
        KEYS[2],
        "last_try", now,
        "next_try", now + 300
    )
end

redis.call("EXPIRE", KEYS[2], 3600)

return 0