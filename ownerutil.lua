local utils = require "kong.tools.utils"
local constants=require "kong.plugins.key-auth.constants"
local apiutil = require "kong.plugins.key-auth.apiutil"
local singletons = require "kong.singletons"
local responses = require "kong.tools.responses"
local crypto = require "crypto"
local cjson = require "cjson.safe"



local _M = {}

--记住用户登录状态
_M.owner_login=function(ownerid)
  local ent, err = singletons.dao.keyauth_ent:find_all {id = ownerid}
  local update_ent, err 
  if ent then
      update_ent, err = singletons.dao.keyauth_ent:update {id = ent.id,ownerid=ent.ownerid,status="1"}
  else
      update_ent, err =singletons.dao.keyauth_ent:insert {id = utils.uuid(),eId=ownerid,status="1"}
  end
  if err then
    return responses.send_HTTP_OK("更新用户状态失败")
  end

end


_M.owner_logout=function (ownerid)
  local ent, err = singletons.dao.keyauth_ent:find_all {id = ownerid}
  local update_ent, err 
  if ent then
      update_ent, err = singletons.dao.keyauth_ent:update {id = ent.id,ownerid=ent.ownerid,status="0"}
  else
      return responses.send_HTTP_OK("无此用户或者用户未登录")
  end
  if err then
    return responses.send_HTTP_OK("更新用户状态失败")
  end
end


return _M
