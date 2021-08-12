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


