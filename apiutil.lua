local utils = require "kong.tools.utils"
local constants=require "kong.plugins.key-auth.constants"
local cjson = require "cjson.safe"
local public_utils = require "kong.tools.public"
local Multipart = require "multipart"
local responses = require "kong.tools.responses"



math.randomseed(os.time())


local _M = {}
--分割字符串 s——字符串 delim——分隔符号
_M.split=function(s, delim)
    if type(delim) ~= "string" or string.len(delim) <= 0 then
        return
    end

    local start = 1
    local t = {}
    while true do
    local pos = string.find (s, delim, start, true) -- plain find
        if not pos then
          break
        end

        table.insert (t, string.sub (s, start, pos - 1))
        start = pos + string.len (delim)
    end
    table.insert (t, string.sub (s, start))

    return t
end


--获取url中的ownerid req.params的键值对
_M.get_uri_params=function (pattern,uri,origparams)
  local params = {}
--如果pattern中无变量，则直接判断uri与pattern是否匹配
  if string.find(pattern,":",1) then
    --local from,_,err=ngx.re.find(uri, pattern, "oj")
--如果pattern中有变量，则依次判断,如果不匹配返回nil，如果匹配则进入下一次判断，如果为变量则放入uri_params中  
    local baseurl=_M.split(uri,"?")[1]
    local uri_vals = _M.split(baseurl,"/")
    local pattern_vals = _M.split(pattern,"/")
    if #uri_vals ~= #pattern_vals then
      return nil
    end
    for i=1,#pattern_vals do
      
      local curstr = pattern_vals[i]
        
      if string.len(curstr)~=0 then
        local startIndex,endIndex = string.find(curstr,":",1)
        --为变量，则存入table
        if startIndex==1 then
          local key = string.gsub(curstr,":","",1)
            params[key]=uri_vals[i]
        --不为变量则判断是否一致
        else
          if pattern_vals[i]~=uri_vals[i] then
            return nil
          end
        end
      end
    end
    local ownerid = params["ownerid"]
    if origparams then
      if ownerid and origparams["ownerid"] then
        if ownerid~=origparams["ownerid"] then
          return responses.send(403,"token的ownerid与接口不一致")
        end
      end
      local restable = utils.table_merge(origparams,params)
      return restable
     else 
      return params
     end
   end

  return nil
end



--将数组scopes转为字符串
_M.generateScope=function(...)
    local scopes = {...}

    local scopeStr=""
    local i,j
    if scopes then
      for i=1,#scopes do
        for j=1,#(scopes[i]) do

          local str=scopeStr
          scopeStr=((i==1 and j==1) and scopes[i][j]["name"]) or str..","..scopes[i][j]["name"]
        end
      end
    end
    return scopeStr
end 

--根据三个参数生成token
_M.generateToken =function(usage,ownerid,tokenId)
    local token = ngx.encode_base64(cjson.encode({["a"]=tokenId,["u"]=ownerid}))
    local tokenEnd=string.gsub(math.random(),".","",2)
    return usage.."."..token.."."..tokenEnd

end 
 



--取出所有的head body url里面的参数 并且放在返回的table里
_M.retrieve_parameters=function()
  ngx.req.read_body()

  local body_parameters, err
  local content_type = ngx.req.get_headers()["content-type"]
  if content_type and string.find(content_type:lower(), "multipart/form-data", nil, true) then
    body_parameters = Multipart(ngx.req.get_body_data(), content_type):get_all()
  elseif content_type and string.find(content_type:lower(), "application/json", nil, true) then
    body_parameters, err = cjson.decode(ngx.req.get_body_data())
    if err then 
      body_parameters = {} 
    end
  else
    body_parameters = public_utils.get_post_args()
  end

  return utils.table_merge(ngx.req.get_uri_args(), body_parameters)
end



--根据当前请求的uri和method从插件目录的常量文件constants中 获取到对应的scope  
_M.getScope=function (uri,method)

  for key,value in pairs(constants) do
    local from,err = _M.get_uri_params(key,uri)


    local baseurl=_M.split(uri,"?")[1]

    if from or key==baseurl then
      for subkey,subvalue in pairs(value) do
        local has,suberr = ngx.re.find(subkey,method,"oj")
        if has then
          return subvalue
        end
      end
    end
  end
  return responses.send(403,"没有设置此接口的scope")
end


return _M
