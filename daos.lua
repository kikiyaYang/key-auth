

local SCHEMA = {
  primary_key = {"id"},
  table = "keyauth_token",
  fields = {
    id = {type = "id", dao_insert_value = true},
    created_at = {type = "timestamp", immutable = true, dao_insert_value = true},
    modified_at = {type = "timestamp", immutable = true, dao_insert_value = true},
    expired_at = {type = "timestamp", immutable = true, dao_insert_value = true},
    note = {type = "string", required = true},
    ownerid = {type = "string", required = true},
    usage = {type = "string", required = false},
    token = {type = "string", required = true},
    scopes = { type = "string", required = true},
    is_self_token={type="bool",required=false,default=true},
    default_token={type="bool",required=false,default=false}
  },
  marshall_event = function(self, t)
    return {id = t.id}
  end
}



local SCOPE_SCHEMA = {
  primary_key = {"id"},
  table="keyauth_scope",
  fields={
    id={type="string",dao_insert_value=true},
    name={type="string",required=true},
    public={type="bool",required=false,default=false},
    description={type="string",required=false}
  },
  marshall_event=function( self,t )
    return {id=t.id}
  end

}

local ENT_SCHEMA = {
  primary_key = {"id"},
  table="keyauth_ent",
  fields={
    id={type="string",dao_insert_value=true},
    status={type="string",required=true},
    ownerid={type="string",required=false,default="0"},
    paytype={type="string",required=false}

    
  },
  marshall_event=function( self,t )
    return {id=t.id}
  end

}


return {keyauth_token =SCHEMA,
        keyauth_scope=SCOPE_SCHEMA,
        keyauth_ent=ENT_SCHEMA
      }
