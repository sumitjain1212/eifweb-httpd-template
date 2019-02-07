
--[[ 
    A configuration such as

    <RequireAll>
      Require valid-user
      Require group eifweb
      Require masquerade endy
    </RequireAll>

    Should allow only members of eifgroup to login, 
    but the remote/logged in user would be named 'endy' not the member's username
    masquerade resets username
 ]]

require "apache2"
function authz_masquerade(r, who)
    r.user = who
    return apache2.AUTHZ_GRANTED
end
