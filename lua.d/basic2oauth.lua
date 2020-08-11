
require 'apache2'
req = require('requests')

local DEBUG_TAG = "eifwebsso.basic2oauth"

-- Just for encoding --
function char_to_hex (c)
    return string.format("%%%02X", string.byte(c))
end

function post_urlencode(data)
    if data == nil then
        return
    end
    data = data:gsub("\n", "\r\n")
    data = data:gsub("([^%w_%-%.~ ])", char_to_hex)
    data = data:gsub(" ", "+")
    return data
end

function dump(o)
    if type(o) == 'table' then
       local s = '{ '
       for k,v in pairs(o) do
          if type(k) ~= 'number' then k = '"'..k..'"' end
          s = s .. '['..k..'] = ' .. dump(v) .. ','
       end
       return s .. '} '
    else
       return tostring(o)
    end
end


-- Just do nothing...
function bypass(r)
    return apache2.OK
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

function is_header_basic(s)
    if s:find("Basic ") then
        return true
    end
    if s:find("basic ") then
        return true
    end
    return false
end

function get_authorization_header_type(s)
    local splitted = string.gmatch(s, '([^ ]+)')
    return splitted()
end

function get_user_from_basic(s)
    local splitted = string.gmatch(s, '([^:]+)')
    return splitted()
end

function get_pass_from_basic(s)
    local splitted = string.gmatch(s, '[^:]+:(.+)')
    return splitted()
end

-- fetch envvar variables by reading the envvars.eifweb file
-- store it in intervm kv pair
function envvar(r)
    local envt = {}
    local envvar_path = r.server_info()["server_root"]  .. "/bin/envvars.eifweb"
    if notempty(r:ivm_get("basic2oauth_sso_url")) and notempty(r:ivm_get("basic2oauth_client_id")) and notempty(r:ivm_get("basic2oauth_client_secret")) and notempty(r:ivm_get("basic2oauth_header")) then
        envt["client_id"] = r:ivm_get("basic2oauth_client_id")
        envt["client_secret"] = r:ivm_get("basic2oauth_client_secret")
        envt["header"] = r:ivm_get("basic2oauth_header")
        envt["sso_url"] = r:ivm_get("basic2oauth_sso_url")
        return envt
    end

    local file = io.open(envvar_path, "rb")
    if file then
        r:err("%s (init) reading file: " .. envvar_path)
        for line in file:lines() do
            if line:match("^##%sFound:%s") and line:match('%sEIF_APACHE_CONF_OIDC_1=([a-z0-9-]+),*%s*') and line:match('%sEIF_APACHE_CONF_OIDC_2=([a-z0-9A-Z]+),*%s*') then
                local client_id = string.match(line, '%sEIF_APACHE_CONF_OIDC_1=([a-z0-9-]+),*%s*')
                local client_secret = string.match(line, '%sEIF_APACHE_CONF_OIDC_2=([a-z0-9A-Z]+),*%s*')
                if notempty(client_id) and notempty(client_secret) then
                    local header = "Basic " .. r:base64_encode(client_id .. ":" .. client_secret)
                    local sso_url = 'https://cloudsso-test.cisco.com/as/token.oauth2'
                    if r.exists_config_define("APPENV_prod") then
                        sso_url = 'https://cloudsso.cisco.com/as/token.oauth2'
                    end
                    r:ivm_set("basic2oauth_client_id", client_id)
                    r:ivm_set("basic2oauth_client_secret", client_secret)
                    r:ivm_set("basic2oauth_header", header)
                    r:ivm_set("basic2oauth_sso_url", sso_url)
                    envt["client_id"] = client_id
                    envt["client_secret"] = client_secret
                    envt["header"] = header
                    envt["sso_url"] = sso_url
                    r:err("%s (init) success sso_url: " .. sso_url)
                    break
                end
            end
        end
    end
    return envt
end

-- intercepts a request which has Authorization header
-- replaces the 'Basic <base64-user:pass>' with 'Bearer <access_token>'
function basic2oauth(r)
    -- look for auth info
    local auth = r.headers_in['Authorization']
    local enable_basic = r.headers_in['X-EIF-BASICAUTH-ENABLE']
    local disable_oauth = r.headers_in['X-EIF-OAUTH-DISABLE']
    local processed_basic2oauth = r.headers_in['X-EIF-BASICAUTH']

    if notempty(enable_basic) then
        return apache2.OK
    end

    if notempty(disable_oauth) then
        return apache2.OK
    end

    if notempty(processed_basic2oauth) then
        return apache2.OK
    end

    if notempty(auth) then

        if is_header_basic(auth) then
            local envt = envvar(r)

            if isempty(envt['sso_url']) or isempty(envt['header']) then
                -- needs to be retried
                r:err(string.format("%s (failure) uri: %s => passing header because: envvar is empty, init failed", r.uri, DEBUG_TAG))
                return apache2.OK
            end

            local sso_url = envt['sso_url']
            local auth_header = envt['header']

            local auth_encoded = string.sub(auth, 7)
            if notempty(auth_encoded) then

                local auth_decoded = r:base64_decode(auth_encoded)
                local cred_user = get_user_from_basic(auth_decoded)
                local cred_pass = get_pass_from_basic(auth_decoded)

                if notempty(cred_user) and notempty(cred_pass) then
                    local req_params = {
                        grant_type = 'password',
                        username = post_urlencode(cred_user),
                        password = post_urlencode(cred_pass)
                    }
                    local req_headers = {
                        ["Content-Type"] = "application/x-www-form-urlencoded",
                        ["Authorization"] = auth_header,
                        ["Cache-Control"] = "no-cache"
                    }
                    r:trace1(string.format("%s (debug) uri: %s => posting credentials to url: %s", r.uri, DEBUG_TAG, sso_url))
                    r:trace1(string.format("%s (debug) uri: %s => posting credentials for user: %s", r.uri, DEBUG_TAG, req_params['username']))
                    -- r:trace1(string.format("%s (debug) posting credentials for pw1: %s", req_params['password']))

                    local res = req.post{
                        sso_url,
                        params = req_params,
                        headers = req_headers,
                        timeout = 15,
                    }

                    if not res then
                        r.headers_in['X-EIF-BASICAUTH'] = string.format("failed 600")
                        r:err("%s (failure) uri: %s => passing header because: api error when fetching access token for username: %s", r.uri, DEBUG_TAG, cred_user)
                        return apache2.OK
                    else
                        -- check status code
                        if res.status_code == 200 then
                            local tab = nil
                            local err = nil
                            tab, err = res.json()
                            if tab ~= nil then
                                if tab.access_token ~= nil then
                                    r.headers_in['Authorization'] = string.format("Bearer %s", tab.access_token)
                                    r.headers_in['X-EIF-BASICAUTH'] = string.format("success")
                                    r:trace1(string.format("%s (debug) uri: %s => insert header for %s with token %s", r.uri, DEBUG_TAG, cred_user, tab.access_token))
                                    r:err(  string.format("%s (success) uri: %s => insert header for %s", r.uri, DEBUG_TAG, cred_user))
                                    return apache2.OK
                                end
                            end
                        else
                            r:trace1(string.format("%s (debug) uri: %s => dumping res from url: %s %s", r.uri, DEBUG_TAG, cred_pass, dump(res)))
                            r:trace1(string.format("%s (debug) uri: %s => dumping res.json() from url: %s %s", r.uri, DEBUG_TAG, cred_pass, dump(res.json())))
                        end
                        -- For all other cases it is a fail
                        r.headers_in['X-EIF-BASICAUTH'] = string.format("failed %s ", res.status_code)
                        r:err(string.format("%s (failure) uri: %s => passing header because: %s returned status %s", r.uri, DEBUG_TAG, sso_url, res.status_code))
                        return apache2.OK
                    end
                end
                -- For all other cases it is a fail
                r.headers_in['X-EIF-BASICAUTH'] = string.format("failed 601")
                r:err("%s (failure) uri: %s => passing header because: empty username or password", r.uri, DEBUG_TAG)
                return apache2.OK
            end
            -- For all basic auth it is a fail
            r.headers_in['X-EIF-BASICAUTH'] = string.format("failed 602")
            r:err("%s (failure) uri: %s => passing header because: invalid basic auth header")
            return apache2.OK
        else
            local auth_header_type = get_authorization_header_type(auth)
            r:err(string.format("%s (bypass) uri: %s => passing header because: auth header type is %s", r.uri, DEBUG_TAG, auth_header_type))
            return apache2.OK
        end
    end
    -- r.headers_in['X-EIF-BASICAUTH'] = string.format("bypass 000")
    return apache2.OK
end


-- disable basic2oauth function
function basic2oauth_disable(r)
    -- r.headers_in['X-EIF-BASICAUTH'] = string.format("disable 000")
    r:err(string.format("%s (disable) uri: %s => insert header for vh: %s", r.uri, DEBUG_TAG, r.hostname))
    return apache2.OK
end
