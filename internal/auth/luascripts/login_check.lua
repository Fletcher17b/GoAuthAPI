local now = tonumber(ARGV[1])

for i = 1, #KEYS do
    local next_try = redis.call("HGET", KEYS[i], "next_try")

    if next_try and tonumber(next_try) > now then
        return 1
    end
end

return 0