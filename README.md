# kongCredential
## 安装

```
curl -X POST http://localhost:8001/apis/ --data "name=mapdesign" --data "upstream_url=http://localhost:3000" --data "methods=POST,PATCH,DELETE,GET,PUT"

curl -X POST http://localhost:8001/apis/mapdesign/plugins --data "name= key-auth"
```
