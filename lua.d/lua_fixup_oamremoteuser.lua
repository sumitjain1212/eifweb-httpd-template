require 'apache2'
require 'string'

function hook(r)
   if r.user ~= nil then
      r:trace1("fixup_oamremoteuser: found user='" .. r.user .. "'")
      l = string.len("uid=")
      if string.sub(r.user, 1, l) == "uid=" then
        n = string.find(r.user, ",", 1)
        if n ~= nil then
          r.user = string.sub(r.user, l + 1, n - 1)
          r:trace1("fixup_oamremoteuser: updated user='" .. r.user .. "'")
        end
      end
   end
   return apache2.OK
end
