local now = tonumber(ARGV[1])

local failures = redis.call("HINCRBY", KEYS[1], "failures", 1)

local next_try = 0

if failures >= 11 then
    next_try = now + 3600
elseif failures >= 6 then
    next_try = now + 300
end

redis.call(
    "HSET",
    KEYS[1],
    "last_try", now,
    "next_try", next_try
)

redis.call("EXPIRE", KEYS[1], 3600)

return 0