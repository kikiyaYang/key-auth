return {
      ["/api/token"]=
        {
          ["GET"]="tokens:read",
          ["POST,PUT,PATCH,DELETE"]="tokens:write"
        },
        ["/styles"]=
        {
          ["GET"]="styles:list",
          ["POST,PUT,PATCH,DELETE"]="styles:write"
         },
         ["/upload/tokens"]=
        {
          ["GET"]="tokens:write"
        }         
}
  