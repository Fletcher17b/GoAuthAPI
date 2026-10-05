local now = tonumber(ARGV[1])
local notify_attempt = tonumber(ARGV[2])

for i = 1, #KEYS do
    local next_try = redis.call("HGET", KEYS[i], "next_try")

    if next_try and tonumber(next_try) > now then
        return 1
    end
end

local notify = false

for i = 1, #KEYS do
    local failures = redis.call("HINCRBY", KEYS[i], "failures", 1)

    local next_try = 0

    if failures >= 11 then
        next_try = now + 3600
    elseif failures >= 6 then
        next_try = now + 300
    end

    redis.call(
        "HSET",
        KEYS[i],
        "last_try", now,
        "next_try", next_try
    )

    redis.call("EXPIRE", KEYS[i], 3600)

    if failures == notify_attempt then
        notify = true
    end
end

if notify then
    return 2
end

return 0