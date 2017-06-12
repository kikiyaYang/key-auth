# kongCredential
##数据库安装 9.4
###初始化数据库目录
initdb pgdb
###启动
pg_ctl -D pgdb -l logfile start
###停止
pg_ctl -D pgdb stop -s -m fast
##数据库安装 9.6
https://wiki.postgresql.org/wiki/YUM_Installation

##创建kong用户
CREATE USER kong; CREATE DATABASE kong OWNER kong;
###配置kong.conf 修改数据库用户名密码,启动kong服务
kong start --conf /etc/conf/kong.conf
##kong 插件目录:
/usr/local/share/lua/5.1/kong/plugins/key-auth/
cp代码到这个目录
## 安装

```
curl -X POST http://localhost:8001/apis/ --data "name=mapdesign" --data "upstream_url=http://localhost:3000" --data "methods=POST,PATCH,DELETE,GET,PUT"

curl -X POST http://localhost:8001/apis/mapdesign/plugins --data "name= key-auth"
```
##kong 插件目录:
/usr/local/share/lua/5.1/kong/plugins/key-auth/