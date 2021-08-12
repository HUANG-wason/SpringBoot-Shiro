# Spring Boot Shiro

筆記:https://blog.csdn.net/weixin_44449838/article/details/108692864

影片:https://www.bilibili.com/video/BV1PE411i7CV?p=44

## 1. 簡介

Apache Shiro是一個強大且易用的Java安全框架

可以完成身份驗證、授權、密碼和會話管理

Shiro 不僅可以用在JavaSE 環境中，也可以用在JavaEE 環境中

官網： http://shiro.apache.org/

---



## 2. 功能

Authentication：身份認證/登錄，驗證用戶是不是擁有相應的身份；

Authorization：授權，即權限驗證，驗證某個已認證的用戶是否擁有某個權限；即判斷用戶是否能做事情，常見的如：驗證某個用戶是否擁有某個角色。或者細粒度的驗證某個用戶對某個資源是否具有某個權限；

Session Manager：會話管理，即用戶登錄後就是一次會話，在沒有退出之前，它的所有信息都在會話中；會話可以是普通JavaSE環境的，也可以是如Web環境的；

Cryptography：加密，保護數據的安全性，如密碼加密存儲到數據庫，而不是明文存儲；

Web Support：Web支持，可以非常容易的集成到Web環境；

Caching：緩存，比如用戶登錄後，其用戶信息、擁有的角色/權限不必每次去查，這樣可以提高效率；

Concurrency：shiro支持多線程應用的並發驗證，即如在一個線程中開啟另一個線程，能把權限自動傳播過去；

Testing：提供測試支持；

Run As：允許一個用戶假裝為另一個用戶（如果他們允許）的身份進行訪問；

Remember Me：記住我，這個是非常常見的功能，即一次登錄後，下次再來的話不用登錄了。

---



## 3. 從外部看

應用代碼直接交互的對像是Subject，也就是說Shiro的對外API核心就是Subject；其每個API的含義：

`Subject`：主體，代表了當前“用戶”，這個用戶不一定是一個具體的人，與當前應用交互的任何東西都是Subject，如網絡爬蟲，機器人等；即一個抽象概念；所有Subject都綁定到SecurityManager，與Subject的所有交互都會委託給SecurityManager；可以把Subject認為是一個門面；SecurityManager才是實際的執行者；

`SecurityManager`：安全管理器；即所有與安全有關的操作都會與SecurityManager交互；且它管理著所有Subject；可以看出它是Shiro的核心，它負責與後邊介紹的其他組件進行交互，如果學習過SpringMVC，你可以把它看成DispatcherServlet前端控制器；

`Realm`：域，Shiro從從Realm獲取安全數據（如用戶、角色、權限），就是說SecurityManager要驗證用戶身份，那麼它需要從Realm獲取相應的用戶進行比較以確定用戶身份是否合法；也需要從Realm得到用戶相應的角色/權限進行驗證用戶是否能進行操作；可以把Realm看成DataSource，即安全數據源。

也就是說對於我們而言，最簡單的一個Shiro應用：

應用代碼通過Subject來進行認證和授權，而Subject又委託給SecurityManager；

我們需要給Shiro的SecurityManager注入Realm，從而讓SecurityManager能得到合法的用戶及其權限進行判斷。

從以上也可以看出，Shiro不提供維護用戶/權限，而是通過Realm讓開發人員自己注入


---

## 4. 外部架構

`Subject`：主體，可以看到主體可以是任何可以與應用交互的“用戶”；

`SecurityManager`：相當於SpringMVC中的DispatcherServlet或者Struts2中的FilterDispatcher；是Shiro的心臟；所有具體的交互都通過SecurityManager進行控制；它管理著所有Subject、且負責進行認證和授權、及會話、緩存的管理。

`Authenticator`：認證器，負責主體認證的，這是一個擴展點，如果用戶覺得Shiro默認的不好，可以自定義實現；其需要認證策略（Authentication Strategy），即什麼情況下算用戶認證通過了；

`Authrizer`：授權器，或者訪問控制器，用來決定主體是否有權限進行相應的操作；即控制著用戶能訪問應用中的哪些功能；

`Realm`：可以有1個或多個Realm，可以認為是安全實體數據源，即用於獲取安全實體的；可以是JDBC實現，也可以是LDAP實現，或者內存實現等等；由用戶提供；注意：Shiro不知道你的用戶/權限存儲在哪及以何種格式存儲；所以我們一般在應用中都需要實現自己的Realm；

`SessionManager`：如果寫過Servlet就應該知道Session的概念，Session呢需要有人去管理它的生命週期，這個組件就是`SessionManager`；而Shiro並不僅僅可以用在Web環境，也可以用在如普通的JavaSE環境、EJB等環境；所有呢，Shiro就抽象了一個自己的Session來管理主體與應用之間交互的數據；這樣的話，比如我們在Web環境用，剛開始是一台Web服務器；接著又上了台EJB服務器；這時想把兩台服務器的會話數據放到一個地方，這個時候就可以實現自己的分佈式會話（如把數據放到Memcached服務器）；

`SessionDAO：DAO`大家都用過，數據訪問對象，用於會話的CRUD，比如我們想把Session保存到數據庫，那麼可以實現自己的`SessionDAO`，通過如JDBC寫到數據庫；比如想把Session放到Memcached中，可以實現自己的Memcached SessionDAO；另外`SessionDAO`中可以使用Cache進行緩存，以提高性能；

`CacheManager`：緩存控制器，來管理如用戶、角色、權限等的緩存的；因為這些數據基本上很少去改變，放到緩存中後可以提高訪問的性能

`Cryptography`：密碼模塊，Shiro提高了一些常見的加密組件用於如密碼加密/解密的

# 2. 快速入門

## 1. 拷貝案例

maven

複製快速入門案例POM.xml 文件中的依賴（版本號自選）

```xml
<dependencies>
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-core</artifactId>
            <version>1.4.1</version>
        </dependency>   
<!-- configure logging -->
    <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>jcl-over-slf4j</artifactId>
        <version>1.7.29</version>
    </dependency>
    <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-log4j12</artifactId>
        <version>1.7.29</version>
    </dependency>
    <dependency>
        <groupId>log4j</groupId>
        <artifactId>log4j</artifactId>
        <version>1.2.17</version>
    </dependency>
</dependencies>
```
## 2.分析案例

>  通過SecurityUtils 獲取當前執行的用戶Subject

```java
Subject currentUser = SecurityUtils.getSubject();
```

>
>  通過當前用戶拿到Session

```java
Session session = currentUser.getSession();
```

>
>  用Session 存值取值

```java
session.setAttribute("someKey", "aValue");
String value = (String) session.getAttribute("someKey");
```

>
>  判斷用戶是否被認證

```java
currentUser.isAuthenticated()
```

>  執行登錄操作

 ```java
currentUser.login(token);
 ```

>
>  打印其標識主體

```java
currentUser.getPrincipal()
```

>  註銷

```java
currentUser.logout();
```

![](D:\黃子瑋\JavaCode\JAVA\JAVA筆記\SpringBoot2\Spring-Boot-Shiro\截圖\shiro.png)

---

# 3. SpringBoot 集成Shiro

Subject 用戶

SecurityManager 管理所有用戶

Realm 連接數據





## 1. 編寫配置文件

pom.xml

```xml
<!--SpringBoot 和 Shiro 整合包-->
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring-boot-web-starter</artifactId>
            <version>1.6.0</version>
        </dependency>
```

>  下面是編寫配置文件
>

-  subject -> ShiroFilterFactoryBean

-  securityManager -> DefaultWebSecurityManager

-  realm

   實際操作中對象創建的順序： realm -> securityManager -> subject



編寫自定義的realm ，需要繼承 `AuthorizingRealm`

```java
package com.example.demo;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class UserRealm extends AuthorizingRealm {

    /**
     * 授權
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //打印一个提示
        System.out.println("執行了授權方法");
        return null;
    }

    /**
     * 驗證
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //打印一个提示
        System.out.println("執行了驗證方法");
        return null;
    }
}
```



新建一個 `ShiroConfig`

```java
package com.example.demo.Config;

import com.example.demo.UserRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {

    // 第三步
    //1. subject -> ShiroFilterFactoryBean
    // @Qualifier("securityManager") 指定 Bean 的名字为 securityManager

    @Bean(name = "shiroFilterFactoryBean")
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("SecurityManager") DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean subject = new ShiroFilterFactoryBean();
        //设置安全管理器
        //需要关联 securityManager ，通过参数把 securityManager 对象传递过来
        subject.setSecurityManager(securityManager);
        return subject;
    }

    // 第二步
    //2. securityManager -> DefaultWebSecurityManager
    // @Qualifier("userRealm") 指定 Bean 的名字为 userRealm
    // spring 默认的 BeanName 就是方法名
    // name 属性 指定 BeanName
    @Bean(name = "SecurityManager")
    public DefaultWebSecurityManager getDefaultWebSecurity(@Qualifier("userRealm") UserRealm userRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        //需要关联自定义的 Realm，通过参数把 Realm 对象传递过来
        securityManager.setRealm(userRealm);
        return securityManager;
    }

    // 第一步
    //3. realm
    //让 spring 托管自定义的 realm 类
    @Bean
    public UserRealm userRealm() {
        return new UserRealm();
    }
}
```

新增 Controller

```java
package com.example.demo.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.jws.WebParam;

@Controller
public class ShiroController {

    @RequestMapping({"/", "/index"})
    public String index(Model model) {
        model.addAttribute("msg", "hello Shiro");
        return "/index";
    }


    @RequestMapping("/add")
    public String add() {
        return "/user/add";
    }

    @RequestMapping("/update")
    public String update() {
        return "/user/update";
    }
}
```



新增 add.html 和 update.html 和 index.html

index.html

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<h1>首頁</h1>
<p th:text="${msg}"></p>
<a th:href="@{/add}">add</a> | <a th:href="@{/update}">update</a>
</body>
</html>
```

add.html 

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<h1>這是 add 頁面</h1>
</body>
</html>
```

update.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<h1>這是 update 頁面</h1>
</body>
</html>
```

![](D:\黃子瑋\JavaCode\JAVA\JAVA筆記\SpringBoot2\Spring-Boot-Shiro\截圖\screenshot_20210809_204402.png)

## 2. 使用

### 1. 登錄攔截

//添加 Shiro 的内置过滤器=======================

>  ​            anon : 无需认证，就可以访问
>
>  ​            authc : 必须认证，才能访问
>
>  ​            user : 必须拥有 “记住我” 功能才能用
>
>  ​            perms : 拥有对某个资源的权限才能访问
>
>  ​            role : 拥有某个角色权限才能访问
>  ​      

ShiroController

```java
package com.example.demo.Config;

import com.example.demo.UserRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class ShiroConfig {

    //1. subject -> ShiroFilterFactoryBean
    // @Qualifier("securityManager") 指定 Bean 的名字为 securityManager
    @Bean(name = "shiroFilterFactoryBean")
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("SecurityManager") DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean subject = new ShiroFilterFactoryBean();

        subject.setSecurityManager(securityManager);

        //添加 Shiro 的内置过滤器=======================
        /*
            anon : 无需认证，就可以访问
            authc : 必须认证，才能访问
            user : 必须拥有 “记住我”功能才能用
            perms : 拥有对某个资源的权限才能访问
            role : 拥有某个角色权限才能访问
         */

        Map<String, String> Map = new LinkedHashMap<>();
        // 設置 /add 請求 必須驗證才能訪問

        Map.put("/add", "authc");
        Map.put("/update", "authc");


        //设置安全管理器
        //需要关联 securityManager ，通过参数把 securityManager 对象传递过来
        subject.setFilterChainDefinitionMap(Map);

        //設置登入的請求
        subject.setLoginUrl("/toLogin");
        return subject;
    }


    //2. securityManager -> DefaultWebSecurityManager
    // @Qualifier("userRealm") 指定 Bean 的名字为 userRealm
    // spring 默认的 BeanName 就是方法名
    // name 属性 指定 BeanName
    @Bean(name = "SecurityManager")
    public DefaultWebSecurityManager getDefaultWebSecurity(@Qualifier("userRealm") UserRealm userRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        //需要关联自定义的 Realm，通过参数把 Realm 对象传递过来
        securityManager.setRealm(userRealm);
        return securityManager;
    }


    //3. realm
    //让 spring 托管自定义的 realm 类
    @Bean
    public UserRealm userRealm() {
        return new UserRealm();
    }
}
```

controller

```java
package com.example.demo.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.jws.WebParam;

@Controller
public class ShiroController {

    @RequestMapping("/toLogin")
    public String toLogin() {
        return "login";
    }

}
```

login.html

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<form action="">
    用戶名:<input type="text" name="username"/><br/>
    密碼:<input type="password" name="password"/><br/>

    <!-- 記住我 -->
    <!-- rememberme須和後台依樣 -->
    <label>
        <input type="checkbox" name="rememberme"> 記住我
    </label>

    <input type="submit" value="登入">
</form>
</body>
</html>
```

點擊 會跳轉到 Login 頁面,即完成攔截

![](D:\黃子瑋\JavaCode\JAVA\JAVA筆記\SpringBoot2\Spring-Boot-Shiro\截圖\screenshot_20210809_204402.png)

![](D:\黃子瑋\JavaCode\JAVA\JAVA筆記\SpringBoot2\Spring-Boot-Shiro\截圖\login.png)

---

### 2. 用戶認證



UserRealm

```java
package com.example.demo;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class UserRealm extends AuthorizingRealm {

    /**
     * 授權
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //打印一个提示
        System.out.println("執行了授權方法");
        return null;
    }

    /**
     * 驗證
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //打印一个提示
        System.out.println("執行了驗證方法");
        return null;
    }
}
```

1. 在Controller 中寫一個登錄的控制器

```java
package com.example.demo.Controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.jws.WebParam;

@Controller
public class ShiroController {

    //登录的方法
    @RequestMapping("/login")
    public String login(String username, String password, Model model) {
        //获取当前用户
        Subject subject = SecurityUtils.getSubject();
        //没有认证过
        //封装用户的登录数据,获得令牌
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);

        //登录 及 异常处理
        try {
            //用户登录
            subject.login(token);
            return "index";

            //如果用户名不存在
        } catch (UnknownAccountException uae) {

            System.out.println("用户名不存在");
            model.addAttribute("msg", "用户名不存在");
            return "login";
        } catch (IncorrectCredentialsException ice) {
            //如果密码错误
            System.out.println("密码错误");
            model.addAttribute("msg", "密码错误");
            return "login";
        }
    }


}
```

![](D:\黃子瑋\JavaCode\JAVA\JAVA筆記\SpringBoot2\Spring-Boot-Shiro\截圖\驗證.png)

**並且可以看出，是先執行了自定義的 `UserRealm``AuthenticationInfo`**

下面去自定義的 `UserRealm``AuthenticationInfo`



修改 `UserRealm``AuthenticationInfo`

```java
package com.example.demo;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class UserRealm extends AuthorizingRealm {

    /**
     * 授權
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //打印一个提示
        System.out.println("執行了授權方法");
        return null;
    }

    /**
     * 驗證
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //打印一个提示
        System.out.println("执行了认证方法");

        // 用户名密码(暂时先自定义一个做测试)
        String name = "root";
        String password = "1234";

        //通过参数获取登录的控制器中生成的 令牌
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        //用户名认证
        if (!token.getUsername().equals(name)) {
            // return null 就表示控制器中抛出的相关异常
            return null;
        }
        //密码认证， Shiro 自己做，为了避免和密码的接触
        //最后返回一个 AuthenticationInfo 接口的实现类，这里选择 SimpleAuthenticationInfo
        // 三个参数：获取当前用户的认证 ； 密码 ； 认证名
        return new SimpleAuthenticationInfo("", password, name);
    }

}
```

Login.html

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<form th:action="@{/login}">
    <p th:text="${msg}" style="color: red;"></p>
    用戶名:<input type="text" name="username"/><br/>
    密碼:<input type="password" name="password"/><br/>

    <!-- 記住我 -->
    <!-- rememberme須和後台依樣 -->
    <label>
        <input type="checkbox" name="rememberme"> 記住我
    </label>

    <input type="submit" value="登入">
</form>
</body>
</html>
```

測試

---

### 3. 退出登錄

1. 在控制器中添加一個退出登錄的方法

```java
//退出登录

@RequestMapping("/logout")
public String logout(){
    Subject subject = SecurityUtils.getSubject();
    subject.logout();
    return "login";
}
```



---

## 3.Shiro 整合 Mybatis

```xml
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
</dependency>

<dependency>
    <groupId>log4j</groupId>
    <artifactId>log4j</artifactId>
    <version>1.2.17</version>
</dependency>

<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>druid</artifactId>
    <version>1.1.12</version>
</dependency>

<dependency>
    <groupId>org.mybatis.spring.boot</groupId>
    <artifactId>mybatis-spring-boot-starter</artifactId>
    <version>2.1.0</version>
</dependency>
```

yaml

```yaml
spring:
  datasource:
    username: root
    password: root
    #?serverTimezone=UTC\u89E3\u51B3\u65F6\u533A\u7684\u62A5\u9519
    url: jdbc:mysql://localhost:3306/mybatis?serverTimezone=UTC&useUnicode=true&characterEncoding=utf-8
    driver-class-name: com.mysql.cj.jdbc.Driver
    type: com.alibaba.druid.pool.DruidDataSource

      #Spring Boot 默认是不注入这些属性值的，需要自己绑定
    #druid 数据源专有配置
    initialSize: 5
    minIdle: 5
    maxActive: 20
    maxWait: 60000
    timeBetweenEvictionRunsMillis: 60000
    minEvictableIdleTimeMillis: 300000
    validationQuery: SELECT 1 FROM DUAL
    testWhileIdle: true
    testOnBorrow: false
    testOnReturn: false
    poolPreparedStatements: true

      #配置监控统计拦截的filters，stat:监控统计、log4j：日志记录、wall：防御sql注入
      #如果允许时报错  java.lang.ClassNotFoundException: org.apache.log4j.Priority
    #则导入 log4j 依赖即可，Maven 地址：https://mvnrepository.com/artifact/log4j/log4j
    filters: stat,wall,log4j
    maxPoolPreparedStatementPerConnectionSize: 20
    useGlobalDataSourceStat: true
    connectionProperties: druid.stat.mergeSql=true;druid.stat.slowSqlMillis=500


#配置 mybatis
mybatis:
  type-aliases-package: com.example.demo.pojo
  mapper-locations: classpath:mapper/*.xml

```

pojo

```java
package com.example.demo.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    private int id;
    private String name;
    private String psw;
}

```

Mapper

```java
package com.example.demo.mapper;

import com.example.demo.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Repository
@Mapper
public interface UserMapper {
    public User queryUserByName(String name);
}

```

Mapper.xml

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.demo.mapper.UserMapper">
    <select id="queryUserByName" parameterType="String" resultType="User">
    select * from mybatis.user where name = #{name}
</select>

</mapper>
```

Service

```java
package com.example.demo.Service;

import com.example.demo.pojo.User;

public interface UserService {
    public User queryUserByName(String name);
}

```

ServiceImpl

```java
package com.example.demo.Service;

import com.example.demo.mapper.UserMapper;
import com.example.demo.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserMapperIpl implements UserService {
    @Autowired
    UserMapper userMapper;

    @Override
    public User queryUserByName(String name) {
        return userMapper.queryUserByName(name);
    }
}

```

Test

```java
package com.example.demo;

import com.example.demo.Service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DemoApplicationTests {
    @Autowired
    UserService userService;

    @Test
    void contextLoads() {
        System.out.println(userService.queryUserByName("kid"));
    }

}
```

---

1.連接資料庫真實數據

UserRealm

```java
package com.example.demo.Config;

import com.example.demo.Service.UserService;
import com.example.demo.pojo.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

public class UserRealm extends AuthorizingRealm {

    // 自動注入 userService
    @Autowired
    private UserService userService;

    /**
     * 授權
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //打印一个提示
        System.out.println("執行了授權方法");
        return null;
    }

    /**
     * 驗證
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //打印一个提示
        System.out.println("执行了认证方法");

        //通过参数获取登录的控制器中生成的 令牌
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

        //連接真實數據庫
        User user = userService.queryUserByName(token.getUsername());

        if (user == null) { // 沒有這個人
            return null; // UnknownAccountException
        }

        //密码认证， Shiro 自己做，为了避免和密码的接触
        //最后返回一个 AuthenticationInfo 接口的实现类，这里选择 SimpleAuthenticationInfo
        // 三个参数：获取当前用户的认证 ； 密码 ； 认证名
        return new SimpleAuthenticationInfo("", user.getPsw(), user.getName());
    }

}
```

---

## 請求授權實現

在數據庫新增一個屬性,用來裝用戶授權

![](D:\黃子瑋\JavaCode\JAVA\JAVA筆記\SpringBoot2\Spring-Boot-Shiro\截圖\screenshot_20210811_210430.png數據庫.png)

ShiroConfig 設置授權

```java
package com.example.demo.Config;

import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class ShiroConfig {

    //1. subject -> ShiroFilterFactoryBean
    // @Qualifier("securityManager") 指定 Bean 的名字为 securityManager
    @Bean(name = "shiroFilterFactoryBean")
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("SecurityManager") DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean subject = new ShiroFilterFactoryBean();

        subject.setSecurityManager(securityManager);

        //添加 Shiro 的内置过滤器=======================
        /*
            anon : 无需认证，就可以访问
            authc : 必须认证，才能访问
            user : 必须拥有 “记住我”功能才能用
            perms : 拥有对某个资源的权限才能访问
            role : 拥有某个角色权限才能访问
         */

        //這裡是用來攔截
        Map<String, String> Map = new LinkedHashMap<>();
        // 設置 /add 請求 必須驗證才能訪問

        //如果訪問/update , 需要有  update 權限
        Map.put("/update", "perms[user:update]");
        Map.put("/add", "perms[user:add]");

        //设置安全管理器
        //需要关联 securityManager ，通过参数把 securityManager 对象传递过来
        subject.setFilterChainDefinitionMap(Map);

        //設置登入的請求
        subject.setLoginUrl("/toLogin");

        //設置未授權的跳轉的頁面
        subject.setUnauthorizedUrl("/noauth");
        return subject;
    }


    //2. securityManager -> DefaultWebSecurityManager
    // @Qualifier("userRealm") 指定 Bean 的名字为 userRealm
    // spring 默认的 BeanName 就是方法名
    // name 属性 指定 BeanName
    @Bean(name = "SecurityManager")
    public DefaultWebSecurityManager getDefaultWebSecurity(@Qualifier("userRealm") UserRealm userRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        //需要关联自定义的 Realm，通过参数把 Realm 对象传递过来
        securityManager.setRealm(userRealm);
        return securityManager;
    }


    //3. realm
    //让 spring 托管自定义的 realm 类
    @Bean
    public UserRealm userRealm() {
        return new UserRealm();
    }
}
```

Controller 設定 未授權跳轉的請求

```java
@RequestMapping("/noauth")
@ResponseBody
public String noauth() {
    return "這是未經授權的用戶";
}
```

UserRealm 連接客戶端與數據庫真實數據

```java
package com.example.demo.Config;

import com.example.demo.Service.UserService;
import com.example.demo.pojo.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

public class UserRealm extends AuthorizingRealm {


    @Autowired
    private UserService userService;

    /**
     * 授權
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //打印一个提示
        System.out.println("執行了授權方法");

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //給所有會員 設置 user:add 權限
//        info.addStringPermission("user:add");

        /**
         * 請求授權實現
         * 連接數據庫
         */
        //拿到當前登入的這個對象 (固定寫法)
        Subject subject = SecurityUtils.getSubject();
        //拿到 User 對象
        User currentUser = (User) subject.getPrincipal();

        //設置當前用戶的權限
        info.addStringPermission(currentUser.getPerms());

        return info;
    }

    /**
     * 驗證
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //打印一个提示
        System.out.println("执行了认证方法");


        // 用户名密码(暂时先自定义一个做测试)
//        String name = "root";
//        String password = "1234";

        //通过参数获取登录的控制器中生成的 令牌
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;


        //連接真實數據庫
        User user = userService.queryUserByName(token.getUsername());

        if (user == null) { // 沒有這個人
            return null; // UnknownAccountException
        }

        //用户名认证
//        if (!token.getUsername().equals(name)) {
//            // return null 就表示控制器中抛出的相关异常
//            return null;
//        }
        //密码认证， Shiro 自己做，为了避免和密码的接触
        //最后返回一个 AuthenticationInfo 接口的实现类，这里选择 SimpleAuthenticationInfo
        // 三个参数：获取当前用户的认证 ； 密码 ； 认证名
        return new SimpleAuthenticationInfo(user, user.getPsw(), user.getName());
    }

}
```

測試

當用 root 帳戶登入時,update 可以進入 ,但無法進入 add

http://localhost:8080/

---

# 4. thymeleaf 整合 shiro

`在 index.html 中 權限的用戶登入才可以看到相對應的請求葉面`

```xml
<!-- thymeleaf 整合 shiro -->
<dependency>
    <groupId>com.github.theborakompanioni</groupId>
    <artifactId>thymeleaf-extras-shiro</artifactId>
    <version>2.0.0</version>
</dependency>
```

ShiroConfig

```java
package com.example.demo.Config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class ShiroConfig {

    @Bean
    //整合 ShiroDialect : 用來整合 Thymeleaf
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }
}
```

index.html

使用 thymeleaf 整合 shiro 需要再 html　導入依賴

>  xmlns:shiro="http://www.thymeleaf.org/thymeleaf-extras-shiro">

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:shiro="http://www.thymeleaf.org/thymeleaf-extras-shiro">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<h1>首頁</h1>
    
<!-- 判斷如果沒有用戶,則顯示'登入' -->
<div th:if="${session.user == null}">
    <a th:href="@{/toLogin}">登入</a>
</div>


<p th:text="${msg}"></p>

<!-- 如果用戶權限有user add 才顯示 -->
<div shiro:hasPermission="user:add">
    <a th:href="@{/add}">add</a>
</div>
    
<div shiro:hasPermission="user:update">
    |<a th:href="@{/update}">update</a>
</div>

</body>
</html>
```

UserRealm 

`在用戶登入後 取得 session 並存取 session,用戶判斷 html 中是否用戶存在`

```java
package com.example.demo.Config;

import com.example.demo.Service.UserService;
import com.example.demo.pojo.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

public class UserRealm extends AuthorizingRealm {


    @Autowired
    private UserService userService;

    /**
     * 授權
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //打印一个提示
        System.out.println("執行了授權方法");

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //給所有會員 設置 user:add 權限
//        info.addStringPermission("user:add");

        /**
         * 連接數據庫
         */
        //拿到當前登入的這個對象 (固定寫法)
        Subject subject = SecurityUtils.getSubject();
        //拿到 User 對象
        User currentUser = (User) subject.getPrincipal();

        //設置當前用戶的權限
        info.addStringPermission(currentUser.getPerms());

        return info;
    }

    /**
     * 驗證
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //打印一个提示
        System.out.println("执行了认证方法");


        // 用户名密码(暂时先自定义一个做测试)
//        String name = "root";
//        String password = "1234";

        //通过参数获取登录的控制器中生成的 令牌
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;


        //連接真實數據庫
        User user = userService.queryUserByName(token.getUsername());

        if (user == null) { // 沒有這個人
            return null; // UnknownAccountException
        }

        /**
         *取得session,並存取用戶
         */
        Subject subject = SecurityUtils.getSubject();
        //獲取 Session
        Session session = subject.getSession();
        session.setAttribute("user", user);

        //用户名认证
//        if (!token.getUsername().equals(name)) {
//            // return null 就表示控制器中抛出的相关异常
//            return null;
//        }
        //密码认证， Shiro 自己做，为了避免和密码的接触
        //最后返回一个 AuthenticationInfo 接口的实现类，这里选择 SimpleAuthenticationInfo
        // 三个参数：获取当前用户的认证 ； 密码 ； 认证名
        return new SimpleAuthenticationInfo(user, user.getPsw(), user.getName());
    }

}
```



