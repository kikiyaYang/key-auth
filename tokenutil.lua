local utils = require "kong.tools.utils"
local constants=require "kong.plugins.key-auth.constants"
local apiutil = require "kong.plugins.key-auth.apiutil"
local singletons = require "kong.singletons"
local responses = require "kong.tools.responses"
local crypto = require "crypto"
local cjson = require "cjson.safe"





local _M = {}

--新增token 参数结构 {["ownerid"]=ownerid,["scopes"]=scopeStr,["note"]=ownerid},usageParam(如果传入则用此参数，此参数不传，则usage取之于前一个params)
_M.issue_token=function(params,isSelfTokenFlag)


    if not params["usage"] then
      params["usage"]= _M.get_usage(params["newscopes"])     
    end

    local tokenVal = apiutil.generateToken(params["usage"],params["ownerid"],id)

    local newtoken = {}
    newtoken["scopes"]=params["newscopes"]
    newtoken["usage"]=params["usage"]
    newtoken["note"]=params["note"]
    newtoken["ownerid"]=params["ownerid"]
    newtoken["is_self_token"]=isSelfTokenFlag



    --已有自身全部scope的token 则只更新
    if isSelfTokenFlag then

      local oritoken,err = singletons.dao.keyauth_token:find_all{is_self_token=true,ownerid=params["ownerid"]}
      if #oritoken>0 then  
        newtoken["id"]=oritoken[1]["id"]

        newtoken["token"]= apiutil.generateToken(params["usage"],params["ownerid"],newtoken["id"])
        singletons.dao.keyauth_token:update(newtoken,{id=newtoken["id"]})  
        return responses.send_HTTP_OK(newtoken["token"])
      end
     end


     --其他请求均为新增
      newtoken["id"]=utils.uuid()
      newtoken["token"]= apiutil.generateToken(params["usage"],params["ownerid"],newtoken["id"])
      newtoken["default_token"]=false
            ngx.log(ngx.ERR,cjson.encode(newtoken).."++++++")

      local tokenres, err = singletons.dao.keyauth_token:insert(newtoken)
   
      return ((not err) and responses.send_HTTP_OK((isSelfTokenFlag and newtoken["token"]) or newtoken)) or responses.send(403,err)


end

--根据当前所有的scopes的name查找scope表，判断usage是公有还是私有类型
_M.get_usage=function(newScopes)

  local usageFlag=true  --默认新建密钥是pk 即public类型

  local myscopes = utils.split(newScopes,",")
  if myscopes then 
    for i=1,#myscopes do
       local credentials, err = singletons.dao.keyauth_scope:find_all{name = myscopes[i]}
        if err then   
          return responses.send_HTTP_OK("scope格式出错")
        end
        ngx.log(ngx.ERR,myscopes[i].."++"..cjson.encode(credentials))

        if credentials[1] and (not credentials[1].public) then
          usageFlag=false
          break
        end
      end
  else
    return responses.send_HTTP_OK("scope格式出错")
  end        
  return (usageFlag and "pk") or "sk"    


end



_M.findScope=function()
  local pkscopes, pkerr = singletons.dao.keyauth_scope:find_all {public = true}
  local skscopes, skerr = singletons.dao.keyauth_scope:find_all {public = false}
  local resscopes = utils.concat(skscopes,pkscopes)
  return responses.send_HTTP_OK(resscopes)
end
--params url参数 isupate，是否是updatetoken 如果是则删除成功后不返回 继续后面的代码，如果为false，则删除成功后返回
--oriUri 为url，用于获取baseurl中的id
_M.delete_token=function(params,isupdate,oriUri)
  local uri_param = (isupdate and "/upload/tokens/:ownerid") or "/api/token/:ownerid/:id"
  local resultparams=apiutil.get_uri_params(uri_param,oriUri,params)
  if resultparams["id"] then
    local tokenres, err = singletons.dao.keyauth_token:delete{id= resultparams["id"]}
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

--oriUri 为url，用于获取baseurl中的id
_M.updateToken=function(params,oriUri)
   local newtoken = {}
   local updateid
   if ngx.re.find(oriUri,"/api/token","oj") then
       local resultparams=apiutil.get_uri_params("/api/token/:ownerid/:id",oriUri,params)

       local token,err = singletons.dao.keyauth_token:find_all {id = resultparams["id"]}
       if resultparams["scopes"] then
          newtoken["scopes"]=resultparams["scopes"]
          newtoken["usage"]=_M.get_usage(resultparams["scopes"])
          newtoken["token"]=apiutil.generateToken(newtoken["usage"],resultparams["ownerid"],resultparams["id"])
          updateid=resultparams["id"]
      end
      if resultparams["note"] then
        newtoken["note"]=resultparams["note"]
      end
    elseif ngx.re.find(oriUri,"/upload/tokens","oj") then
      local newtokens,err=singletons.dao.keyauth_token:find_all{token=params["token"]}
      newtoken=newtokens[1]
      newtoken["token"]=apiutil.generateToken(newtoken["usage"],newtoken["ownerid"],newtoken["id"])
      updateid=newtoken["id"]
    end

    local update_token, err = singletons.dao.keyauth_token:update(newtoken,{id = updateid})
    return responses.send_HTTP_OK(update_token["token"])
end


--获取某个用户全部密钥
_M.get_token=function(params)

    --判断是否有权限
    local tokens,err = singletons.dao.keyauth_token:find_all {ownerid = params["ownerid"],is_self_token= false}
    if not err then           
      --local isvalid = string.find(token[1]["scopes"],"tokens:read",1)
      --if isvalid then
      return responses.send_HTTP_OK(tokens)
      -- else 
      --   return responses.send_HTTP_OK("此token不包含查看所有token的权限")
      -- end
    else 
      return responses.send(403,err)
    end
end



_M.get_tokenAgent=function (token)

    local tempmsg=apiutil.split(token,".")
       
    local tokenstr=ngx.decode_base64(tempmsg[2])

    return cjson.decode(tokenstr)
end


return _M
