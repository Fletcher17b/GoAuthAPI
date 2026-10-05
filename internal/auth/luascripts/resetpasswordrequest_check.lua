local now = tonumber(ARGV[1])

for i = 1, #KEYS do
    local next_try = redis.call("HGET", KEYS[i], "next_try")

    if next_try and tonumber(next_try) > now then
        return 1
    end
end

-- IP window: 1 minute
local ip_window = redis.call("HGET", KEYS[1], "window_start")
local ip_attempts = tonumber(redis.call("HGET", KEYS[1], "attempts") or 0)

if ip_window and now - tonumber(ip_window) < 60 and ip_attempts >= 3 then
    return 1
end

-- Account window: 1 hour
local account_window = redis.call("HGET", KEYS[2], "window_start")
local account_attempts = tonumber(redis.call("HGET", KEYS[2], "attempts") or 0)

if account_window and now - tonumber(account_window) < 3600 and account_attempts >= 3 then
    return 1
end

return 0