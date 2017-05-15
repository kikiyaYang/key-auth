return {
      ["/api/token"]=
        {
          ["GET"]="tokens:read",
          ["POST,PUT,PATCH,DELETE"]="tokens:write"
        }
}
  