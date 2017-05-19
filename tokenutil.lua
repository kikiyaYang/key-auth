local utils = require "kong.tools.utils"
local constants=require "kong.plugins.key-auth.constants"
local apiutil = require "kong.plugins.key-auth.apiutil"
local singletons = require "kong.singletons"
local responses = require "kong.tools.responses"
local crypto = require "crypto"
local cjson = require "cjson.safe"



local _M = {}

--新增token 参数结构 {["ownerid"]=ownerid,["scopes"]=scopeStr,["note"]=ownerid},usageParam(如果传入则用此参数，此参数不传，则usage取之于前一个params)
_M.issue_token=function(params)
  
  --判断是否有权限

  local isvalid = string.find(params["scopes"],"tokens:write",1)
  if true then
    local id= utils.uuid()

    if not params["usage"] then
      params["usage"]= _M.get_usage(params["scopes"])     
    end

    local tokenVal = apiutil.generateToken(params["usage"],params["ownerid"],id)
    local tokenres, err = singletons.dao.keyauth_token:insert({
      id = id,
      ownerid=params["ownerid"],
      scopes =params["scopes"],
      note=params["note"],
      usage=params["usage"],
      token=tokenVal
      })
      if params["selfuse"] then
        return tokenres
      else
        return ((not err) and responses.send_HTTP_OK(tokenres)) or responses.send_HTTP_OK("新建token出错")
      end
    else 
      return responses.send_HTTP_OK("此token不包含新增token的权限")
    end
end

--根据当前所有的scopes的name查找scope表，判断usage是公有还是私有类型
_M.get_usage=function(newScopes)

  local usageFlag=true  --默认新建密钥是pk 即public类型

  local myscopes = utils.split(newScopes,",")
  if myscopes then 
    for i=1,#myscopes do
       local credentials, err = singletons.dao.keyauth_scope:find_all {name = myscopes[i]}
        if err then 
          return responses.send_HTTP_OK("scope格式出错")
        end

        if not credentials[1].public then
          usageFlag=false
          break
        end
      end
  else
    return responses.send_HTTP_OK("scope格式出错")
  end        
  return (usageFlag and "pk") or "sk"      

end

--params url参数 isupate，是否是updatetoken 如果是则删除成功后不返回 继续后面的代码，如果为false，则删除成功后返回
_M.delete_token=function(params,isupdate)
       
  if params["id"] then
    local tokenres, err = singletons.dao.keyauth_token:delete{id= params["id"]}
    if tokenres then
      if not isupdate then
        return responses.send_HTTP_OK("删除token成功")
      end
    end
    if err then
       return responses.send_HTTP_OK("删除token失败")
     end
  else 
    return responses.send_HTTP_OK("缺少参数id")
  end
end


_M.updateToken=function(params)
   local token,err = singletons.dao.keyauth_token:find_all {id = params["id"]}
   local newtoken = {}
   if params["scopes"] then
    newtoken["scopes"]=params["scopes"]
  end
  if params["note"] then
    newtoken["note"]=params["note"]
  end

   newtoken["usage"]=_M.get_usage(params["scopes"])
    local update_token, err = singletons.dao.keyauth_token:update(newtoken,{id = params["id"]})
    return responses.send_HTTP_OK(update_token)
end


--获取某个用户全部密钥
_M.get_token=function(params)

    --判断是否有权限
    local token,err = singletons.dao.keyauth_token:find_all {ownerid = params["ownerid"]}
    if token then           
      local isvalid = string.find(token[1]["scopes"],"tokens:read",1)
      if isvalid then
        local credentials, err = singletons.dao.keyauth_token:find_all {ownerid = params["ownerid"]}
        return responses.send_HTTP_OK(credentials)
      else 
        return responses.send_HTTP_OK("此token不包含查看所有token的权限")
      end
    else 
      return responses.send_HTTP_OK("token有误")
    end
end



_M.get_tokenAgent=function (token)

    local tempmsg=apiutil.split(token,".")
       
    local tokenstr=ngx.decode_base64(tempmsg[2])

    return cjson.decode(tokenstr)
end


return _M
