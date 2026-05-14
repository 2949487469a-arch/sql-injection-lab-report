-   **1.概述**
    - 实验来源：PortSwigger Web Security Academy
    - 实验名称：Blind SQL injection with conditional responses
    - 目标：通过布尔盲注逐字符提取管理员密码，以管理员身份登录
- **2.漏洞原理简介**
  - -应用根据查询结果是否为空返回不同的页面内容（出现/不出现 “Welcome back” 消息）。

  -   利用该条件差异，通过构造 `AND` 条件式，推断数据库信息

-   **3.实验环境**    
    -   靶场：PortSwigger Lab
        
    -   工具：Burp Suite Community（Repeater、Intruder）
    
    **4.漏洞发现**    
    
      - 4.1 识别可疑参数
使用 Burp 拦截首页请求，发现 Cookie 中有 `TrackingId`。  
![输入图片说明](./imgs/2026-05-14/fb564243-d6b5-4921-a00d-12f0aaa5958f.png)
该参数常用于用户追踪，极有可能被服务端存入数据库并在每次请求时查询。

    - 4.2 确认注入点
为什么用 `AND` 而不是直接加单引号？
因为直接加单引号可能只触发语法错误，无法稳定提取信息。使用burp对抓包发现，对其`TrackingId`加入一个单引号，发现其两次查询物品的响应都会返回一个welcome back，没有明显的报错回显，因此尝试进入到布尔测试，构建 `AND`表达式，通过页面内容差异来判断。
![输入图片说明](/imgs/2026-05-14/tIzrOrxHJ9wKMYpF.png)
    -  使用 `AND` 可以将一个可控的布尔条件“绑”在原始查询之后，让页面响应直接反映该条件的真假。
 
**具体测试步骤：**
1. 构造永真条件  
   `TrackingId=xyz' AND '1'='1`  
   → 页面出现 “Welcome back”，说明数据库查询正常返回结果。
   ![输入图片说明](/imgs/2026-05-14/CUVwVwe6L6eysGnZ.png)
2. 构造永假条件  
   `TrackingId=xyz' AND '1'='2`  
   → 页面 **不** 出现 “Welcome back”，说明 `AND '1'='2'` 让整个条件为假。
   ![输入图片说明](/imgs/2026-05-14/tGAjCVcrPaqHC4Rn.png)
**结论：**  
两次测试的响应差异证实 `TrackingId` 参数存在 SQL 注入，且为**条件响应型布尔盲注**。注入点位于 Cookie 值中，闭合方式为单引号。
**5.漏洞利用** 
   - 5.1 确认 users 表存在
`TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`
（这个payload的意义：如果存在一个users表，就临时*创建*一个a取出来与另一个a对比，则永真返回welcome back，而如果表不存在，取不出来就是一个空值与a对比，永假不返回welcome back，这里的a值可以是任意值，并不是之前存在在users表中的，加LIMIT 1主要是只返回一行数据，防止子查询会返回多行 `'a'`，与 `'a'` 比较会直接导致数据库报错（“子查询返回多于一行”），可能使应用抛出 500 错误，干扰测试）
![输入图片说明](/imgs/2026-05-14/2bg56Qqay81TfXuV.png)
“Welcome back” 出现 → `users` 表存在。
   - 5.2 确认  administrator 用户存在
`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
![输入图片说明](/imgs/2026-05-14/23EDpd0ZFIR89cgN.png)
“Welcome back” 出现 → 用户 `administrator` 存在。

   - 5.3 判断密码长度
使用 `LENGTH(password)>N` 逐步递增 `N` 进行测试。  
当 `N=20` 时，“Welcome back” **消失**，确定密码长度为 20 个字符。`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a`
将包发送到Burp中的intruder中来进行密码长度验证，使用sinper模式中的number对密码长度位置进行单参数遍历一至二十
（为什么不直接猜测密码，先测试密码长度？-   先确定长度是一种**工程优化**，用很少的请求换取清晰的边界，让后续猜解过程更高效、可靠。）
![输入图片说明](/imgs/2026-05-14/dnfcTFc4wCQUd2j2.png)
![输入图片说明](/imgs/2026-05-14/BYBrMUC6x97GwCLr.png)
这里19的时候还是返回welcome，20不返回，从length上面也可以分析出来到二十响应length明显发生变化，因此确定其密码长度大于19小于20

- 5.4 逐字符爆破密码
`AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`（ subs前面的参数是位置，后面的参数是数量，不同的数据库版本略有不同，需要时再查询）
使用 Burp Intruder 发起攻击：
   - Payload 位置：`SUBSTRING(password,§1§,1)` `'§a§`  
  - Payload 集合：a-z, 0-9  （用**Brute forcer**）
  - Grep-Match：设置匹配 “Welcome back”  直接可以看响应的内容哪里出现了welcome back，记得clear其他的内容
  - 依次执行偏移 1 到 20，收集所有字符，拼接得到完整密码

这里对两个参数进行对比，使用inturder的**Custom iterator**来进行同时遍历，进而求出每个位置的密码
![输入图片说明](/imgs/2026-05-14/6MAehGmC69af0FVT.png)
对第一个参数密码位置用Numbers，不需要a-z
![输入图片说明](/imgs/2026-05-14/Z3fVgOmLIBg9J3Wi.png)
对第二个参数密码的值用Brute forcer，，注意时使用Brute forcer的时候长度min和max都要设置为1，不然组合数过多，也可以是其他的，例如simper list，但是需要手动输入字符，也可以创建一个文件用来存储可能的密码值，需要用的load上去就行，这里不作演示

![输入图片说明](/imgs/2026-05-14/vBi9iiIc8A9Arq8u.png)
因为使用的是社区版的burp，所以遍历的比较慢，需要跑的比较久，如果用专业版的话会快很多，最近根据上面显示出来的的得到密码的组合。

 **6.结果验证**
- 使用爆破出的密码在 `/my-account` 页面登录，成功以 `administrator` 身份进入，完成实验

**7.修复建议** 
- 使用参数化查询（Prepared Statement）处理 Cookie 值。
- 对用户输入进行严格类型校验，避免直接拼接到 SQL 语句。

**8.修复建议** 
- 掌握了基于条件响应的布尔盲注完整利用链。
- 深入理解了 `AND` 条件在盲注中的作用，以及如何通过页面差异推断数据。
- 熟练使用 Burp Suite 的 Intruder 模块进行自动化字符爆破。
