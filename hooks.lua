local events = require "kong.core.events"
local cache = require "kong.tools.database_cache"

local function invalidate(message_t)
if message_t.collection == "keyauth_token" then
    cache.delete(cache.keyauth_token_key(message_t.old_entity and message_t.old_entity.id or message_t.entity.id))
  end
end

return {
  [events.TYPES.ENTITY_UPDATED] = function(message_t)
    invalidate(message_t)
  end,
  [events.TYPES.ENTITY_DELETED] = function(message_t)
    invalidate(message_t)
  end
}