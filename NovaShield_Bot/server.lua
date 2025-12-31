local API_URL = "http://5.253.246.173/api/heartbeat"
local API_SECRET = "MEIN_SUPER_SECRET"
local LICENSE_KEY = "DEIN_LIZENZ_KEY"
local RESOURCE_NAME = GetCurrentResourceName()

CreateThread(function()
    while true do
        local serverName = GetConvar("sv_hostname", "unknown")
        local endpoint = GetCurrentServerEndpoint()
        local ip, port = "unknown", "unknown"

        if endpoint ~= nil then
            local split = {}
            for token in string.gmatch(endpoint, "[^:]+") do
                table.insert(split, token)
            end
            ip = split[1] or "unknown"
            port = split[2] or "unknown"
        end

        PerformHttpRequest(API_URL, function(status, body, headers)
            -- print("Heartbeat:", status, body)
        end, "POST", json.encode({
            license_key = LICENSE_KEY,
            server_name = serverName,
            server_ip = ip,
            server_port = port,
            resource_name = RESOURCE_NAME
        }), {
            ["Content-Type"] = "application/json",
            ["x-api-secret"] = API_SECRET
        })

        Wait(60000)
    end
end)
