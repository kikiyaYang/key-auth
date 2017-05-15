local cache = require "kong.tools.database_cache"
local responses = require "kong.tools.responses"

local singletons = require "kong.singletons"
local BasePlugin = require "kong.plugins.base_plugin"
local apiutil = require "kong.plugins.key-auth.apiutil"
local tokenutil = require "kong.plugins.key-auth.tokenutil"


local cjson = require "cjson.safe"


local ngx_set_header = ngx.req.set_header
local ngx_get_headers = ngx.req.get_headers
local set_uri_args = ngx.req.set_uri_args
local get_uri_args = ngx.req.get_uri_args
local clear_header = ngx.req.clear_header



local params = {}
local KeyAuthHandler = BasePlugin:extend()

KeyAuthHandler.PRIORITY = 1000

function KeyAuthHandler:new()
  KeyAuthHandler.super.new(self, "key-auth")
end



local function load_credential(keyid)

  local creds, err = singletons.dao.keyauth_token:find_all {
    id = keyid
  }

  if not creds then
    return nil, err
  end

  return creds[1].scopes
end






local function unserialize(str)  
  local EMPTY_TABLE = {} 
    if str == nil or str == "nil" then  
        return nil  
    elseif type(str) ~= "string" then  
        EMPTY_TABLE = {}  
        return EMPTY_TABLE  
    elseif #str == 0 then  
        EMPTY_TABLE = {}  
        return EMPTY_TABLE  
    end  
  
    local code, ret = pcall(loadstring(string.format("do local _=%s return _ end", str)))  
  
    if code then  
        return ret  
    else  
        EMPTY_TABLE = {}  
        return EMPTY_TABLE  
    end  
end  



local function to_utf8(a)  
  local n, r, u = tonumber(a)  
  if n<0x80 then                        -- 1 byte  
    return char(n)  
  elseif n<0x800 then                   -- 2 byte  
    u, n = tail(n, 1)  
    return char(n+0xc0) .. u  
  elseif n<0x10000 then                 -- 3 byte  
    u, n = tail(n, 2)  
    return char(n+0xe0) .. u  
  elseif n<0x200000 then                -- 4 byte  
    u, n = tail(n, 3)  
    return char(n+0xf0) .. u  
  elseif n<0x4000000 then               -- 5 byte  
    u, n = tail(n, 4)  
    return char(n+0xf8) .. u  
  else                                  -- 6 byte  
    u, n = tail(n, 5)  
    return char(n+0xfc) .. u  
  end  
end 

function setOwnerid(pattern) 
  local oriUri=apiutil.split(ngx.req.raw_header()," ")[2]

  local paramtable = apiutil.get_uri_params(pattern,oriUri)
    if paramtable and paramtable["ownerid"] then
     params["ownerid"]=paramtable["ownerid"]
   end
end

function checkpropToken(method)
  local res,err
  if method=="GET" then

      setOwnerid("/core/tokens/:ownerid")

      setOwnerid("/uploads/tokens/:ownerid")

      --判断url的ownerid与token中的ownerid是否一致
      local access_token = params["access_token"]
      if access_token then
        local access_ownerid = tokenutil.get_tokenAgent(access_token)["u"]
        if access_ownerid~=params["ownerid"] then
          err="wrong ownerid"
        end
      end


      local scopes_public= singletons.dao.keyauth_scope:find_all{public=true}
      local scopes = singletons.dao.keyauth_scope:find_all{public = false}


      local scopeStr = apiutil.generateScope(scopes_public,scopes)
      local ownerid = params['ownerid']
      local tokenParams = {["selfuse"]=true,["ownerid"]=ownerid,["scopes"]=scopeStr,["note"]=ownerid,["usage"]="sk"}

      local tokenRes=tokenutil.issue_token(tokenParams)

      res = apiutil.generateToken("sk",ownerid,tokenRes["id"])
    end
    return res,err
end



function checkLogin(  )
    local from, _, err = ngx.re.find(ngx.var.uri, [[\/doLogin]], "oj")
    if from  then

    end
end

 

function KeyAuthHandler:access(conf)
  KeyAuthHandler.super.access(self)


  --所有参数
  params = apiutil.retrieve_parameters()
  local method= ngx.req.get_method()

  checkLogin()

  -- --处理登录注册，getScope，生成用户token和token刷新
  local res,err=checkpropToken(method)
  if res then
    return responses.send_HTTP_OK(res)
  end
  if err then 
    return responses.send_HTTP_OK(err)
  end

  local from, _, err = ngx.re.find(ngx.var.uri, [[\/api\/token]], "oj")



  --token放在head或者body里面都可以
  local token = params["token"]

  local tokenObj = {}




  --token的增删改查必须在gateway处理，此url必须带token参数
    if not token then
      --如果token的增删改查无token参数则报错
      if from then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR("参数有误缺少token")
      --如果其他url无token参数则转发
      --else 

       end
    else
      --如果有token参数，先判断token的格式是否正确
      local tokenObj=tokenutil.get_tokenAgent(token)
      params["ownerid"]=tokenObj["u"]
      params["tokenid"]=tokenObj["a"]
      if not params["ownerid"] then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR("token有误缺少ownerid信息")
      end

      if not params["tokenid"] then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR("token有误缺少tokenid信息")
      end

      --如果token的格式正确，url为token的增删改查，则在本地处理数据库
      if from then
        if method=="POST" then
           tokenutil.issue_token(params)
        elseif method=="GET" then
            tokenutil.get_token(params)
         -- elseif method== "PATCH"
         -- elseif method=="DELETE" 
        end
  
      --如果token的格式正确，url为其他接口，
      --则根据token的id对应的scopes数据判断是否有此接口的权限，
      --如果此token的权限包含此接口的权限，则把token中的用户id连接到url后再转发
      --（upstream服务器端判断如果有此用户id则使用此用户id，无此用户id则使用session中的用户id，都没有则报错）
      else 
        local scopes=load_credential(params["tokenid"])
        local myscopes=apiutil.getScope(ngx.var.uri,method)

        local flag = false

        for i = 1, #myscopes do

            local index = string.find(scopes,myscopes[i], 1)

            if not index then
              break
            elseif i==#myscopes then
              flag=true
            end
         end
         
         if flag then
            ngx.req.set_uri(ngx.ctx.uri.."/"..params["ownerid"])
         end

    end
   end
   return responses.send_HTTP_OK("nothing")
end

return KeyAuthHandler
