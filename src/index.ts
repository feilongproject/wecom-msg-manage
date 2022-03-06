
import xml2js from 'xml2js'
import { Buffer } from 'buffer'
import { createHash, createDecipheriv, randomBytes, createCipheriv } from 'crypto';
import fetch from 'node-fetch';


export class WxCom {
    AgentId: number;
    Secret: string;
    Id: string;
    Token: string;
    EncodingAESKey: string;
    /**
     * 构造一个企业应用
     * @param AgentId 应用ID
     * @param Secret 应用密钥
     * @param Id 企业ID
     * @param Token 接受信息时设置的Token
     * @param EncodingAESKey 接受信息时设置的EncodingAESKey
     */
    constructor(AgentId: number, Secret: string, Id: string, Token: string, EncodingAESKey: string) {
        this.AgentId = AgentId;
        this.Secret = Secret;
        this.Id = Id;
        this.Token = Token;
        this.EncodingAESKey = EncodingAESKey;
    }


    async GetToken(): Promise<Token> {

        const NewToken: Token = await fetch(`https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${this.Id}&corpsecret=${this.Secret}`).then(async res => {
            //const r: any = res.json()
            //console.log(`New Token: ${JSON.stringify(r)}`)
            return JSON.parse(await res.text());
        })
        return NewToken;
    }


    /**
     * 
     * @param body 接收数据主体
     * @param msg_signature 消息签名
     * @param timestamp 时间戳
     * @param nonce 随机数
     * @returns 解密后的消息
     */
    async MsgDecode(body: string, msg_signature: string, timestamp: number, nonce: number,): Promise<textMessage | picMessage | voiceMessage> {
        //console.log(body)
        var receBody: receBody = await xml2js.parseStringPromise(body).then((res) => {
            return res.xml;
        }).then(res => {
            return {
                ToUserName: res.ToUserName[0],
                AgentID: res.AgentID[0],
                Encrypt: res.Encrypt[0],
            };
        });


        let pc = new Prpcrypt(this.EncodingAESKey);

        //此时返回的是明文XML，需要转换为对象
        let echoStrXml = pc.decrypt(receBody.Encrypt);

        return await xml2js.parseStringPromise(echoStrXml.msg).then((res) => {
            return res.xml
        }).then(res => {
            //console.log(`${JSON.stringify(res)}`)
            console.log(`xml to json: ${JSON.stringify(res)}`)
            var MsgType = res.MsgType[0]
            switch (MsgType) {
                case "text":
                    return {
                        ToUserName: res.ToUserName[0],
                        FromUserName: res.FromUserName[0],
                        CreateTime: res.CreateTime[0],
                        MsgType: MsgType,
                        Content: res.Content[0],
                        MsgId: res.MsgId[0],
                        AgentID: res.AgentID[0],
                    };
                case "image":
                    return {
                        ToUserName: res.ToUserName[0],
                        FromUserName: res.FromUserName[0],
                        CreateTime: res.CreateTime[0],
                        MsgType: res.MsgType[0],
                        PicUrl: res.PicUrl[0],
                        MsgId: res.MsgId[0],
                        MediaId: res.MediaId[0],
                        AgentID: res.AgentID[0],
                    };
                case "voice":
                    return {
                        ToUserName: res.ToUserName[0],
                        FromUserName: res.FromUserName[0],
                        CreateTime: res.CreateTime[0],
                        MsgType: res.MsgType[0],
                        MediaId: res.MediaId[0],
                        Format: res.Format[0],
                        MsgId: res.MsgId[0],
                        AgentID: res.AgentID[0],
                    };
                default:
                    throw Error("unkown msg type");
            }

        })


    }
    async MsgTest(body: string,) {
        var receBody: receBody = {
            ToUserName: "test",
            AgentID: this.AgentId,
            Encrypt: body
        }

        let EncryptMsg = receBody.Encrypt;

        let pc = new Prpcrypt(this.EncodingAESKey);

        //此时返回的是明文XML，需要转换为对象
        let echoStrXml = pc.decrypt(EncryptMsg);
        //console.log(echoStrXml)

        return echoStrXml

    }


}

class Prpcrypt {
    key: Buffer
    iv: Buffer
    constructor(k: string) {
        this.key = Buffer.from(k + '=', 'base64');
        this.iv = this.key.slice(0, 16);
    }

    /**
     * 加密
     * @param {string} xmlMsg 原始需要加密的消息
     * @param {string} receiveId 
     */
    encrypt(xmlMsg: string, receiveId: string) {

        // 1. 生成随机字节流
        let random16 = randomBytes(16);
        // 2. 将明文消息转换为 buffer
        let msg = Buffer.from(xmlMsg);
        // 3. 生成四字节的 Buffer
        let msgLength = Buffer.alloc(4);
        // 4. 生成4个字节的msg长度
        msgLength.writeUInt32BE(msg.length, 0);
        // 5. 将corpId以二进制的方式写入内存
        let corpId = Buffer.from(receiveId);
        // 6. 拼接成 buffer
        let raw_msg = Buffer.concat([random16, msgLength, msg, corpId]);
        // 7. 加密 创建加密对象
        let cipher = createCipheriv('aes-256-cbc', this.key, this.iv);
        // 8. 取消自动填充
        cipher.setAutoPadding(false);
        // 9. 使用 PKCS#7 填充
        raw_msg = this.PKCS7Encoder(raw_msg);
        let cipheredMsg = Buffer.concat([cipher.update(/*encoded*/raw_msg), cipher.final()]);
        return cipheredMsg.toString('base64');

    }

    /**
     * 解密
     * @param {mix} encrypted 
     * @param {number} receiveId 
     */
    decrypt(encrypted: string,) {

        let aesCipher = createDecipheriv("aes-256-cbc", this.key, this.iv);
        aesCipher.setAutoPadding(false); //不自动切断

        let decipheredBuff = Buffer.concat([aesCipher.update(encrypted, 'base64'), aesCipher.final()]);
        decipheredBuff = this.PKCS7Decoder(decipheredBuff);

        const random = decipheredBuff.slice(0, 16).toString();         // 16个随机字节的random
        const msg_len = decipheredBuff.slice(16, 20).readUInt32BE(0);  // 4个字节的msg_len
        const msg = decipheredBuff.slice(20, msg_len + 20).toString(); // 最终的消息体原文msg
        const CorpID = decipheredBuff.slice(msg_len + 20).toString();  // 尾部的CorpID

        return {
            random,
            msg_len,
            msg,
            CorpID
        }; // 返回一个解密后的明文

    }

    /**
     * 对需要加密的明文进行填充补位
     * @param {*} text 需要进行填充补位操作的明文
     */
    PKCS7Encoder(text: Buffer) {
        const blockSize = 32;
        const textLength = text.length;
        // 计算需要填充的位数
        const amountToPad = blockSize - (textLength % blockSize);
        const result = Buffer.alloc(amountToPad);
        result.fill(amountToPad);
        return Buffer.concat([text, result]);
    }
    /**
     * 
     * 对解密后的明文进行补位删除
     * @param {string} buff 解密后的明文
     */
    PKCS7Decoder(buff: Buffer) {
        var pad = buff[buff.length - 1];
        if (pad < 1 || pad > 32) {
            pad = 0;
        }
        return buff.slice(0, buff.length - pad);
    }

}

interface Token {
    "errcode": number,
    "errmsg": string,
    "access_token": string,
    "expires_in": number,
    "add_in": number,
}

interface receBody {
    ToUserName: string,
    AgentID: number,
    Encrypt: string,
}

interface textMessage {
    ToUserName: string;
    FromUserName: string;
    CreateTime: number;
    MsgType: "text";
    Content: string;
    MsgId: string;
    AgentID: string;
}

interface picMessage {
    ToUserName: string;
    FromUserName: string;
    CreateTime: number;
    MsgType: "image";
    PicUrl: string;
    MediaId: string;
    MsgId: number;
    AgentID: number;
}

interface voiceMessage {
    ToUserName: string;
    FromUserName: string;
    CreateTime: number;
    MsgType: "voice";
    MediaId: string;
    Format: string;
    MsgId: number;
    AgentID: number;
}