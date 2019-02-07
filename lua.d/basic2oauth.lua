require 'apache2'
req = require('requests')

sso_url = 'https://cloudsso-test.cisco.com/as/token.oauth2'
sso_cred = "Basic ZWlmLW9pZGMtbnByZDpmcU9wZ1hXQmpUT0FiTkFDYWdydzVLVUJoYVU3Q05BM0tMWHltdE5tcTBrTDRZVmw5NTRNdkhYaTc0ekJWQXZy"

-- fake authcheck hook
-- If request has no auth info, set the response header and
-- return a 401 to ask the browser for basic auth info.
-- If request has auth info, don't actually look at it, just
-- pretend we got userid 'foo' and validated it.
-- Then check if the userid is 'foo' and accept the request.
function basic2oauth(r)

    local oidc_key = r.subprocess_env['EIF_APACHE_CONF_OIDC_1']
    local oidc_secret = r.subprocess_env['EIF_APACHE_CONF_OIDC_2']
    r:error(string.format("basic2oauth oidc_key: %s", oidc_key))

    -- look for auth info
    auth = r.headers_in['Authorization']
    if auth ~= nil then
        local auth_table = {}
        local cred_table = {}
        local auth_decoded = nil
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
                        r:error(string.format("basic2oauth (process) found authorization header for username: %s", cred_table[1]))
                        local req_params = {
                            grant_type = 'password',
                            username = cred_table[1],
                            password = cred_table[2]
                        }
                        local req_headers = {
                            ["Content-Type"] = "application/x-www-form-urlencoded",
                            ["Authorization"] = sso_cred,
                            ["Cache-Control"] = "no-cache"
                        }
                        r:trace1(string.format("basic2oauth posting credentials to url: %s", sso_url))
                        local res = req.post{
                            sso_url,
                            params = req_params,
                            headers = req_headers,
                            timeout = 15,
                        }

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
                                        r:error(string.format("basic2oauth (success) adding access_token: %s", tab.access_token))
                                        return apache2.OK
                                    else
                                        r:debug(string.format("basic2oauth (pass-thru) no access_token found in: %s", tab))
                                        return apache2.OK
                                    end
                                else
                                    r:debug(string.format("basic2oauth (pass-thru) %s returned error %s", idp_url, err))
                                    return apache2.OK
                                end
                           else
                                r:debug(string.format("basic2oauth (pass-thru) %s returned status %s", idp_url, res.status_code))
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