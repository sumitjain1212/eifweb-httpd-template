require 'apache2'
req = require('requests')

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
        r:err("basic2oauth (init) reading file: " .. envvar_path)
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
                    r:err("basic2oauth (init) success sso_url: " .. sso_url)
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
    auth = r.headers_in['Authorization']
    if auth ~= nil then
        local auth_table = {}
        local cred_table = {}
        local auth_decoded = nil
        local envt = envvar(r)
        if isempty(envt['sso_url']) or isempty(envt['header']) then
            r:err("basic2oauth (pass-thru) envvar is empty, init failed")
            return apache2.OK
        end
        local sso_url = envt['sso_url']
        local auth_header = envt['header']
        for word in auth:gmatch("%w+") do
            table.insert(auth_table, word)
        end
        if auth_table[1] ~= nil then
            if auth_table[1]:lower() == 'basic' then
                if auth_table[2] ~= nil then
                    local auth_decoded = r:base64_decode(auth_table[2])
                    for word in auth_decoded:gmatch("[^:]+") do
                        table.insert(cred_table, word)
                    end
                    if #cred_table == 2 then
                        local req_params = {
                            grant_type = 'password',
                            username = cred_table[1],
                            password = cred_table[2]
                        }
                        local req_headers = {
                            ["Content-Type"] = "application/x-www-form-urlencoded",
                            ["Authorization"] = auth_header,
                            ["Cache-Control"] = "no-cache"
                        }
                        r:trace1(string.format("basic2oauth posting credentials for username: %s to url: %s", req_params['username'], sso_url))
                        local res = req.post{
                            sso_url,
                            params = req_params,
                            headers = req_headers,
                            timeout = 15,
                        }

                        if cred_table[1] == 'gautsing.test' then
                            r:trace1(string.format("basic2oauth sleeping for 100 seconds"))
                            os.execute("sleep " .. tonumber(100))
                        end
                        
                        if not res then
                            r:err("basic2oauth (pass-thru) unable to fetch access token for username: %s", cred_table[1])
                            return apache2.OK
                        else
                            if res.status_code == 200 then
                                local tab = nil
                                local err = nil
                                tab, err = res.json()
                                if tab ~= nil then
                                    if tab.access_token ~= nil then
                                        r.headers_in['Authorization'] = string.format("Bearer %s", tab.access_token)
                                        r.headers_in['X-Basic-2-OAuth'] = string.format("%d", os.time())
                                        r:trace1(string.format("basic2oauth (sucess) insert header for %s@%s", cred_table[1], tab.access_token))
                                        r:err(   string.format("basic2oauth (sucess) insert header for %s", cred_table[1]))
                                        return apache2.OK
                                    else
                                        r:debug(string.format("basic2oauth (pass-thru) no access_token found in: %s", tab))
                                        return apache2.OK
                                    end
                                else
                                    r:debug(string.format("basic2oauth (pass-thru) %s returned error %s", sso_url, err))
                                    return apache2.OK
                                end
                           else
                                r:debug(string.format("basic2oauth (pass-thru) %s returned status %s", sso_url, res.status_code))
                                return apache2.OK
                            end
                        end
                    else
                        r:debug("basic2oauth (pass-thru) invalid authorization header")
                        return apache2.OK
                    end
                end
            else
                r:debug(string.format("basic2oauth (pass-thru) skipping '%s' type Authorization header", auth_table[1]:lower()))
                return apache2.OK
            end
        end
    end
    return apache2.OK
end
