# wecom-msg-manage
企业微信应用接发消息控制

## 安装模块
```bash
npm install wecom-msg-manage
```

## 导入模块
- js
```js
WxCom = require('wecom-msg-manage');
```
- ts
```ts
import { WxCom } from "wecom-msg-manage";
```
## 使用模块
- 初始化企业微信应用对象
```ts
const wxcom = new WxCom(
    AgentId,         //应用AgentId
    Secret,          //应用Secret
    CId,             //企业ID
    token,           //接收消息服务器Token
    EncodingAESKey,  //接收消息服务器EncodingAESKey
    )                
```

- 验证URL有效性
```ts
return await wxcom.MsgTest(echostr)//传入echostr
```

- 解密传入信息（当请求方式为POST时可用）
```ts
const decode = await wxcom.MsgDecode(
    receBody,        //传入主体
    msg_signature,   //传入签名
    timestamp,       //传入时间戳
    nonce,           //传入nonce
    )

```
- 获取Token
```ts
var Token = wxcom.GetToken()
```

# TODO
- 添加发送消息功能
