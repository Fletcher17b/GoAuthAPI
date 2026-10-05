local now = tonumber(ARGV[1])

local next_try = redis.call("HGET", KEYS[1], "next_try")

if next_try and tonumber(next_try) > now then
    return 1
end

return 0