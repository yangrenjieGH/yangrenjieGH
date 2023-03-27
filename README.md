



bili:https://www.bilibili.com/video/BV17h41147Jq

P31-35章节视频示例

P36-43章节示例：https://gitee.com/hhgs_admin/jjwtdemo

P44章节实例

# 一，令牌模式

## 一：获取授权码

### 1，服务起来后访问地址：

http://localhost:8080/oauth/authorize?response_type=code&client_id=admin&redirect_uri=http://www.baidu.com&scope=all

账号：admin

密码：123456

### 2，登录成功后选择授权

选择==Approve==  然后点击 ==Authorize==按钮

![image-20211205140755761](images/image-20211205140755761.png)

### 3，获取跳转成功后的地址上的授权码==gnVz51==

https://www.baidu.com/?code=gnVz51



## 二，获取令牌

### 4，通过postman传递授权码，获取资源的访问令牌。

这里的账号和密码是授权配置类==AuthorizationServerConfig==中配置的账号密码

![image-20211205141249346](images/image-20211205141249346.png)

body图示：

![image-20211205141358197](images/image-20211205141358197.png)

body中的参数：

```
grant_type:authorization_code
code:gnVz51
client_id:admin
redirect_uri:http://www.baidu.com
scope:all
```

##### 5,Send发送

返回结果：

access_token就是请求资源用的令牌

```json
{
    "access_token": "804d1721-c910-4276-a592-83e1dc12afb1",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "all"
}
```



三，获取资源

### 5,请求地址：

http://localhost:8080/user/getCurrentUser

Authorization选择的是：Bearer Token

值是上一步获取到的令牌==804d1721-c910-4276-a592-83e1dc12afb1==

![image-20211205141716171](images/image-20211205141716171.png)

结果：

```json
{
    "password": null,
    "username": "admin",
    "authorities": [
        {
            "authority": "admin"
        }
    ],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
}
```



# 二，密码模式

## 1，修改配置类

SecurityConfig类新增：

```java
   @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
```

## 2，修改授权类型

AuthorizationServerConfig类修改两处：

1，修改.authorizedGrantTypes("authorization_code") 改为：.authorizedGrantTypes("password")

2，新增

```
  /**
     * @description: 使用密码模式所需配置
     * @author liyonghui
     * @date 2021/12/5 14:27
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager).userDetailsService(userService);
    }
```

## 3，测试获取令牌

地址：http://localhost:8080/oauth/token

这里没变化

![image-20211205143525577](images/image-20211205143525577.png)

body参数调整：

```
grant_type:password
username:admin
scope:all
password:123456
```

图示：

![image-20211205143602187](images/image-20211205143602187.png)



## 4，通过令牌获取资源

![image-20211205143651070](images/image-20211205143651070.png)



# 三，令牌存放到Redis

## 1，新增依赖

pom.xml新增

```xml
       <!-- https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-data-redis -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <!-- https://mvnrepository.com/artifact/org.apache.commons/commons-pool2 -->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-pool2</artifactId>
        </dependency>

```

application.properties新增

```properties
spring.redis.host=127.0.0.1
spring.redis.port=6379
spring.redis.password=123456
```

## 2，修改逻辑

RedisConfig文件新增

```java

    @Bean
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
```

AuthorizationServerConfig文件修改

新增tokenStore(redisTokenStore)

```java
    @Autowired
    @Qualifier("redisTokenStore")
    private TokenStore redisTokenStore;

    /**
     * @description: 使用密码模式所需配置
     * @author liyonghui
     * @date 2021/12/5 14:27
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager).userDetailsService(userService)
                .tokenStore(redisTokenStore);
    }
```

## 3，重新获取令牌

![image-20211205145223110](images/image-20211205145223110.png)

## 4，此时令牌已存入redis

![image-20211205145254968](images/image-20211205145254968.png)



# 四，SpringSecurityOauth2整合JWT

## 1，先去掉redis相关配置

pom.xml

```xml
   <!-- https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-data-redis -->
     <!--   <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        &lt;!&ndash; https://mvnrepository.com/artifact/org.apache.commons/commons-pool2 &ndash;&gt;
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-pool2</artifactId>
        </dependency>-->

```

application.properties

```properties
#spring.redis.host=127.0.0.1
#spring.redis.port=6379
#spring.redis.password=123456

```

RedisConfig

```java
//@Configuration
public class RedisConfig {

//    @Autowired
//    private RedisConnectionFactory redisConnectionFactory;
//
//    @Bean
//    public TokenStore redisTokenStore() {
//        return new RedisTokenStore(redisConnectionFactory);
//    }
}

```

AuthorizationServerConfig

```java
    //    @Autowired
//    @Qualifier("redisTokenStore")
//    private TokenStore redisTokenStore;
   @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager).userDetailsService(userService)
//                .tokenStore(redisTokenStore);
;
    }
```



## 2，新增JWT逻辑

新增配置类JwtTokenStoreConfig

```java
/**
 * @author liyonghui
 * @description: TODO
 * @date 2021/12/5 15:39
 */
@Configuration
public class JwtTokenStoreConfig {

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        //配置JWT使用的秘钥
        jwtAccessTokenConverter.setSigningKey("test_key");
        return jwtAccessTokenConverter;
    }
}

```

修改AuthorizationServerConfig

```java
    @Autowired
    @Qualifier("jwtTokenStore")
    private TokenStore jwtTokenStore;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    /**
     * @description: 使用密码模式所需配置
     * @author liyonghui
     * @date 2021/12/5 14:27
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager).userDetailsService(userService)
//                .tokenStore(redisTokenStore);
                //配置存储令牌策略
                .tokenStore(jwtTokenStore)
                .accessTokenConverter(jwtAccessTokenConverter)
        ;
    }
```



## 3，测试查看生成的token效果

![image-20211205154836497](images/image-20211205154836497.png)



生成的token:

```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2Mzg3MzM0MDEsInVzZXJfbmFtZSI6ImFkbWluIiwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiODZmY2ZmNWYtNGYzZS00MGRkLWE3ZTctODgyYWE2YTcyM2E5IiwiY2xpZW50X2lkIjoiYWRtaW4iLCJzY29wZSI6WyJhbGwiXX0.D8gaC9bC1iWhFXzyARCDSf7Db2e5EZFBC9F93UgYryI",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "all",
    "jti": "86fcff5f-4f3e-40dd-a7e7-882aa6a723a9"
}
```

## 4，官网解析

https://jwt.io/

解析结果：

![image-20211205155307168](images/image-20211205155307168.png)



# 五，扩展JWT中存储的内容-P45

## 1，新增逻辑

新增类：

```java
/**
 * @author liyonghui
 * @description: JWT内容增强
 * @date 2021/12/5 15:58
 */
public class JwtTokenEnhancer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        Map<String, Object> objectObjectHashMap = new HashMap<>();
        objectObjectHashMap.put("enhance", "enhance info");
        objectObjectHashMap.put("ceshi", "张三");
        ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(objectObjectHashMap);
        return oAuth2AccessToken;
    }
}
```



JwtTokenStoreConfig类新增：

```java
@Bean
public JwtTokenEnhancer jwtTokenEnhancer() {
    return new JwtTokenEnhancer();
}
```



AuthorizationServerConfig修改

```java
@Autowired
    private JwtTokenEnhancer jwtTokenEnhancer;

    /**
     * @description: 使用密码模式所需配置
     * @author liyonghui
     * @date 2021/12/5 14:27
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //配置JWT内容增强
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();
        delegates.add(jwtTokenEnhancer);
        delegates.add(jwtAccessTokenConverter);
        tokenEnhancerChain.setTokenEnhancers(delegates);

        endpoints.authenticationManager(authenticationManager).userDetailsService(userService)
//                .tokenStore(redisTokenStore);
                //配置存储令牌策略
                .tokenStore(jwtTokenStore)
                .accessTokenConverter(jwtAccessTokenConverter)
                .tokenEnhancer(tokenEnhancerChain)
        ;
    }
```

## 2，重启服务测试

![image-20211205160927335](images/image-20211205160927335.png)



返回结果：

```java
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjZXNoaSI6IuW8oOS4iSIsInVzZXJfbmFtZSI6ImFkbWluIiwic2NvcGUiOlsiYWxsIl0sImV4cCI6MTYzODczNDc3MSwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiODNkN2E1ODktOWVlNC00MjEwLTk4MTYtM2VkYTg3ZjkyMmVjIiwiY2xpZW50X2lkIjoiYWRtaW4iLCJlbmhhbmNlIjoiZW5oYW5jZSBpbmZvIn0.yM4ch_cIKtnr0WuBImqUQqfVlHA9dJ7uw75OLV5ozhE",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "all",
    "ceshi": "张三",
    "enhance": "enhance info",
    "jti": "83d7a589-9ee4-4210-9816-3eda87f922ec"
}
```

3，官网解析

https://jwt.io/



![image-20211205161017135](images/image-20211205161017135.png)



# 七，解析JWTtoken中的内容

## 1，新增依赖

pom.xml

```xml
<!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

## 2,修改接口

UserController新增

```java
 /**
     * @description: 解析JWT
     * @author liyonghui
     * @date 2021/12/5 16:18
     */
    @RequestMapping("getCurrentUser1")
    public Object getCurrentUser1(Authentication authentication, HttpServletRequest request) {
        String head = request.getHeader("Authorization");
        String token = head.substring(head.indexOf("bearer") + 7);
        return Jwts.parser().setSigningKey("test_key".getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token).getBody();
    }
```

## 3,重启服务并获取令牌。

## 4，用获取到的令牌下发请求调用getCurrentUser1接口

http://localhost:8080/user/getCurrentUser1
Headers

```
Authorization:bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjZXNoaSI6IuW8oOS4iSIsInVzZXJfbmFtZSI6ImFkbWluIiwic2NvcGUiOlsiYWxsIl0sImV4cCI6MTYzODczNTYxNCwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiOWQ5YTk1OWEtZDA1MS00YzMzLWIwMzUtNGQyYzc0MTcwNTQxIiwiY2xpZW50X2lkIjoiYWRtaW4iLCJlbmhhbmNlIjoiZW5oYW5jZSBpbmZvIn0.8F73_hlNLgkrwuda1ZJwX5AstI16o2fU8leMiNjU5_o
```



返回结果：

```
{
    "ceshi": "张三",
    "user_name": "admin",
    "scope": [
        "all"
    ],
    "exp": 1638735614,
    "authorities": [
        "admin"
    ],
    "jti": "9d9a959a-d051-4c33-b035-4d2c74170541",
    "client_id": "admin",
    "enhance": "enhance info"
}
```

### 效果图： 

![image-20211205162235433](images/image-20211205162235433.png)



# 八，刷新令牌

## 1，修改AuthorizationServerConfig

```
 //授权类型-使用密码模式
                .authorizedGrantTypes("password","refresh_token","authorization_code")
```

## 2,先获取令牌，可以用密码模式或者令牌模式获取。

举例：密码模式先获取令牌，此时返回值里面多了个refresh_token-此为刷新令牌使用。

```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjZXNoaSI6IuW8oOS4iSIsInVzZXJfbmFtZSI6ImFkbWluIiwic2NvcGUiOlsiYWxsIl0sImV4cCI6MTYzODczNjAzOSwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiZGIzNWY2YTItNDRhOS00N2Q5LWFmZmMtNTI1MzM4NTgyNTA1IiwiY2xpZW50X2lkIjoiYWRtaW4iLCJlbmhhbmNlIjoiZW5oYW5jZSBpbmZvIn0.wYsKpNhSbhNeOUjINzLJcg5Tdthn5-a4ZgAkbFucvrw",
    "token_type": "bearer",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjZXNoaSI6IuW8oOS4iSIsInVzZXJfbmFtZSI6ImFkbWluIiwic2NvcGUiOlsiYWxsIl0sImF0aSI6ImRiMzVmNmEyLTQ0YTktNDdkOS1hZmZjLTUyNTMzODU4MjUwNSIsImV4cCI6MTY0MTI4NDgzOSwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiNjczZjljMjQtNzMxZi00OGM3LWI2MWItNmYyOTllNWE5YjBkIiwiY2xpZW50X2lkIjoiYWRtaW4iLCJlbmhhbmNlIjoiZW5oYW5jZSBpbmZvIn0.Hpt06vxsVHdTCQZwsEyeVGnEAAIrH3X17FyyPNRaLwE",
    "expires_in": 43199,
    "scope": "all",
    "ceshi": "张三",
    "enhance": "enhance info",
    "jti": "db35f6a2-44a9-47d9-affc-525338582505"
}
```

图示：

![image-20211205162955931](images/image-20211205162955931.png)

## 3，刷新令牌

地址：http://localhost:8080/oauth/token

Authorization不变：

![image-20211205163131228](images/image-20211205163131228.png)

Body值：

```
grant_type:refresh_token
refresh_token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjZXNoaSI6IuW8oOS4iSIsInVzZXJfbmFtZSI6ImFkbWluIiwic2NvcGUiOlsiYWxsIl0sImF0aSI6ImRiMzVmNmEyLTQ0YTktNDdkOS1hZmZjLTUyNTMzODU4MjUwNSIsImV4cCI6MTY0MTI4NDgzOSwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiNjczZjljMjQtNzMxZi00OGM3LWI2MWItNmYyOTllNWE5YjBkIiwiY2xpZW50X2lkIjoiYWRtaW4iLCJlbmhhbmNlIjoiZW5oYW5jZSBpbmZvIn0.Hpt06vxsVHdTCQZwsEyeVGnEAAIrH3X17FyyPNRaLwE
```

返回新的令牌

图示：

![image-20211205163103672](images/image-20211205163103672.png)

# 九，SpringSecurityOauth2整合SSO

```
client端源码地址：https://gitee.com/hhgs_admin/oauth2clientdemo.git
```



## 1，新建项目

![image-20220715102959665](images/image-20220715102959665.png)

![image-20220715103028023](images/image-20220715103028023.png)

后续一路下一步创建。

## 2，引入依赖

pom.xml新增依赖

```xml
  <properties>
        <java.version>1.8</java.version>
        <spring-cloud.version>Greenwich.SR2</spring-cloud.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.0</version>
        </dependency>
        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-all</artifactId>
            <version>4.6.3</version>
        </dependency>
    </dependencies>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
```



## 3，新增配置

application.properties新增配置

```properties
server.port=8081
#防止Cookie冲突，冲突会导致登录验证不通过
server.servlet.session.cookie.name=OAUTH2-CLIENT-SESSIONID01
#授权服务器地址
oauth2-server-url=http://localhost:8080
#于授权服务器对应的配置
security.oauth2.client.client-id=admin
security.oauth2.client.client-secret=112233
security.oauth2.client.user-authorization-uri=${oauth2-server-url}/oauth/authorize
security.oauth2.client.access-token-uri=${oauth2-server-url}/oauth/token
security.oauth2.resource.jwt.key-uri=${oauth2-server-url}/oauth/token_key
```



## 4，新增注解

启动类新增注解@EnableOAuth2Sso

```java
package com.yonghui.oauth2clientdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;


@SpringBootApplication
//开启单点登录功能
@EnableOAuth2Sso
public class Oauth2clientdemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2clientdemoApplication.class, args);
    }

}

```



## 5，新增方法

新增测试方法

```java
package com.yonghui.oauth2clientdemo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication) {
        return authentication;
    }

}

```



## 6，服务端修改

//路径：com.yonghui.springsecurityoauth2demo.config.AuthorizationServerConfig.java

```java
@Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                //配置client-id
                .withClient("admin")
                //配置client-secret
                .secret(passwordEncoder.encode("112233"))
                //配置访问token的有效期
//                .accessTokenValiditySeconds(3600)
                //配置刷新令牌的有效期
                .refreshTokenValiditySeconds(864000)
                //配置redirect-url,用于授权成功后跳转
                .redirectUris("http://localhost:8081/login")
                //自动授权
                .autoApprove(true)
                //配置申请的权限范围
                .scopes("all")
                //配置grant_type，表示授权类型（authorization_code：令牌模式）
//                .authorizedGrantTypes("authorization_code")
                //授权类型-使用密码模式
                .authorizedGrantTypes("password","refresh_token","authorization_code")
        ;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //获取密钥需要身份认证,使用单点登录时必须配置
        security.tokenKeyAccess("isAuthenticated()");

    }
```

效果图：

![image-20220715103409875](images/image-20220715103409875.png)

## 7，测试访问

```
先启动服务端 springsecurityoauth2-demo
再启动客户端 oauth2clientdemo
访问地址：http://localhost:8081/user/getCurrentUser
【
1，发现浏览器自动跳转到“http://localhost:8080/login”页面。
2，此时输入的账号密码是在服务端的UserService类中设置的账号密码哦，
3，输入成功后页面跳转到“getCurrentUser”接口，正常展示接口返回的数据，效果如下图所示。
】
```



//服务端代码

```java
//springsecurityoauth2-demo
package com.yonghui.springsecurityoauth2demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * @author liyonghui
 * @description: TODO
 * @date 2021/12/5 13:34
 */
@Service
public class UserService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        String password = passwordEncoder.encode("123456");
        return new User("admin", password, AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
```

下图输入：admin/123456

![image-20220715103725776](images/image-20220715103725776.png)

登录成功后的页面信息：

![image-20220715103852010](images/image-20220715103852010.png)

