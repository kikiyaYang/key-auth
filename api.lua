local crud = require "kong.api.crud_helpers"
local utils = require "kong.tools.utils"
local apiutil = require "kong.plugins.key-auth.apiutil"

return {
  ["/"] = {
     before = function(self, dao_factory, helpers)
      return helpers.responses.send_HTTP_OK("000")
     end
  },
  ["/api/token/:ownerid"] = {
     before = function(self, dao_factory, helpers)

      local filter_keys={ownerid=self.params.ownerid}
      local tokens,err= dao_factory.keyauth_token:find_all(filter_keys)
      self.tokens=tokens

      local newTokenId = utils.uuid()
      local ownerid = self.params.ownerid
      self.params.id=newTokenId
      self.params.ownerid=ownerid
      self.params.token=apiutil.generateToken("pk",ownerid,newTokenId)

     end,

     GET = function(self, dao_factory,helpers)
       return helpers.responses.send_HTTP_OK(self.tokens)
     end,

     POST = function(self, dao_factory,helpers)

        crud.post(self.params, dao_factory.keyauth_token) 

      end
  },

  ["/api/token/:ownerid/:id"] = {
    before = function(self, dao_factory, helpers)

      local filter_keys = {
          id=self.params.id,
          ownerid=self.params.ownerid
      }

      local credentials, err = dao_factory.keyauth_token:find_all(filter_keys)
      if err then
        return helpers.yield_error(err)
      elseif next(credentials) == nil then
        return helpers.responses.send_HTTP_NOT_FOUND()
      end

      self.token = credentials[1]

      self.params.scopes=apiutil.generateScope(self.params.scopes)  
    end,

    PATCH = function(self, dao_factory)
      crud.patch(self.params, dao_factory.keyauth_token, self.token)
    end,

    DELETE = function(self, dao_factory)
      crud.delete(self.token, dao_factory.keyauth_token)
    end
  }
}
