return {
      ["/api/token"]=
        {
          ["GET"]="tokens:read",
          ["POST,PUT,PATCH,DELETE"]="tokens:write"
        },
        ["/styleSet"]=
        {
          ["GET"]="styles:read",
          ["POST,PUT,PATCH,DELETE"]="styles:write"
         },
         ["/upload/tokens"]=
        {
          ["GET"]="tokens:write"
        }         
}
  