

require 'apache2'
req = require('requests')
json = require 'lunajson'
local DEBUG_TAG = "eifweb.OpaPreAuthnAccess"
-----------------------------------------------
-- Helpers:
-----------------------------------------------
function dump(node)
    local cache, stack, output = {},{},{}
    local depth = 1
    local output_str = "{\n"
    while true do
        local size = 0
        for k,v in pairs(node) do
            size = size + 1
        end
        local cur_index = 1
        for k,v in pairs(node) do
            if (cache[node] == nil) or (cur_index >= cache[node]) then
                if (string.find(output_str,"}",output_str:len())) then
                    output_str = output_str .. ",\n"
                elseif not (string.find(output_str,"\n",output_str:len())) then
                    output_str = output_str .. "\n"
                end
                -- This is necessary for working with HUGE tables otherwise we run out of memory using concat on huge strings
                table.insert(output,output_str)
                output_str = ""
                local key
                if (type(k) == "number" or type(k) == "boolean") then
                    key = "["..tostring(k).."]"
                else
                    key = "['"..tostring(k).."']"
                end
                if (type(v) == "number" or type(v) == "boolean") then
                    output_str = output_str .. string.rep('\t',depth) .. key .. " = "..tostring(v)
                elseif (type(v) == "table") then
                    output_str = output_str .. string.rep('\t',depth) .. key .. " = {\n"
                    table.insert(stack,node)
                    table.insert(stack,v)
                    cache[node] = cur_index+1
                    break
                else
                    output_str = output_str .. string.rep('\t',depth) .. key .. " = '"..tostring(v).."'"
                end
                if (cur_index == size) then
                    output_str = output_str .. "\n" .. string.rep('\t',depth-1) .. "}"
                else
                    output_str = output_str .. ","
                end
            else
                -- close the table
                if (cur_index == size) then
                    output_str = output_str .. "\n" .. string.rep('\t',depth-1) .. "}"
                end
            end
            cur_index = cur_index + 1
        end
        if (size == 0) then
            output_str = output_str .. "\n" .. string.rep('\t',depth-1) .. "}"
        end
        if (#stack > 0) then
            node = stack[#stack]
            stack[#stack] = nil
            depth = cache[node] == nil and depth + 1 or depth - 1
        else
            break
        end
    end
    -- This is necessary for working with HUGE tables otherwise we run out of memory using concat on huge strings
    table.insert(output,output_str)
    output_str = table.concat(output)
    return output_str
end

function notempty(s)
    if s == nil or s == '' then
        return false
    end
    return true
end


function isempty(s)
    if notempty(s) then
        return false
    end
    return true
end

function get_req_json(r)
    local headers = {}
    for k, v in pairs(r.headers_in) do
        if notempty(v) and notempty(k) then
            headers[k] = v
        end
    end
    local apache_req = {}
    apache_req["headers"] = headers
    -- r.headers_in
    apache_req["host"] = r.hostname or "0.0.0.0"
    apache_req["method"] = r.method or "unknown"
    apache_req["parsed_uri"] = r.uri or "/"
    apache_req["uri"] = r.r.unparsed_uri or "/"
    apache_req["full_url"] = string.format("%s://%s:%s%s",
        r.is_https and "https" or "http",
        r.hostname,
        r.port,
        r.unparsed_uri)
    apache_req["useragent_ip"] = r.useragent_ip or "0.0.0.0"
    apache_req["server_name"] = r.server_name or "0.0.0.0"
    apache_req["port"] = r.port or 0
    apache_req["protocol"] = r.protocol or "unknown"
    apache_req["is_https"] = r.is_https
    apache_req["is_initial_req"] = r.is_initial_req
    apache_req["user"] = r.user or "anonymous"
    r:debug(string.format("%s -> uri: %s, id: %s, dump: %s", DEBUG_TAG, r.uri, r.log_id, dump(apache_req)))
    -- r:debug(string.format("%s -> uri: %s, id: %s, json: %s", DEBUG_TAG, r.uri, r.log_id, json.encode(apache_req)))
    return json.encode(apache_req)
    -- return dump(apache_req)
end


-- /path/to/script.lua --
function logger(r)

    local fn = string.format("/opt/eif/web/temp/%s.log", DEBUG_TAG)
    local f = io.open(fn, "a")
    local j = get_req_json(r)

    if f then
        f:write(os.date("%c") .. "\n".. j.. "\n\n")
        f:close()
    end
    return apache2.DONE
end