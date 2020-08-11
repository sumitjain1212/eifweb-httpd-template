require 'apache2'


local DEBUG_TAG = "eifwebsso.accesslevel"


function is_not_empty(s)
    if s == nil or s == '' then
        return false
    end
    return true
end


function handler(r)
    local result = apache2.DECLINED
    local user = r.user
    r:debug(string.format("%s handler for uri: %s", DEBUG_TAG, r.uri))

    if is_not_empty(user) then
        local env = r.subprocess_env
        local claimed_access_level = env["OIDC_CLAIM_accesslevel"]
        r:debug(string.format("%s handler for uri: %s, user: %s", DEBUG_TAG, r.uri, r.user))
        if is_not_empty(claimed_access_level) then
            r:info(string.format("%s claimed access_level: %s", DEBUG_TAG, claimed_access_level))
            if not string.match(claimed_access_level, '^4$') then
                r:info(string.format("%s denied access for user: %s with access_level: %s", DEBUG_TAG, user, claimed_access_level))
                r.status = 403
                r:custom_response(403, "Forbidden access level")
                result = 403
            else
                r:info(string.format("%s allowed access for user: %s with access_level: %s", DEBUG_TAG, user, claimed_access_level))
                result = apache2.DECLINED
            end
        end
   end
   return result
end