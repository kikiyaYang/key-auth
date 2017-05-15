

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
    isdeleted = { type = "bool", required = false,default=false}
  },
  marshall_event = function(self, t)
    return {id = t.id, ownerid= t.ownerid}
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
    return {id=t.id,name=t.name,public=t.public}
  end

}

local ENT_SCHEMA = {
  primary_key = {"id"},
  table="keyauth_ent",
  fields={
    id={type="string",dao_insert_value=true},
    name={type="string",required=true},
    status={type="string",required=true},
    eId={type="string",required=false,default="0"},
    password={type="string",required=true},
    secrete={type="string",required=true},
    validateTime={type = "timestamp", immutable = true, dao_insert_value = true},
    createTime={type = "timestamp", immutable = true, dao_insert_value = true},
    modifyTime={type = "timestamp", immutable = true, dao_insert_value = true},
    isDeleted = { type = "string", required = false,default="0"},
    __v={ type = "string", required = false}
  },
  marshall_event=function( self,t )
    return {id=t.id}
  end

}


return {keyauth_token =SCHEMA,
        keyauth_scope=SCOPE_SCHEMA,
        keyauth_ent=ENT_SCHEMA
      }
