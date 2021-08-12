package com.example.demo.Controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Repository;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ShiroController {


//    @RequestMapping("/")
//    public String index(Model model) {
//        model.addAttribute("msg", "hello Shiro");
//        return "/test";
//    }

    @RequestMapping("/")
    public String index(Model model) {
        model.addAttribute("msg", "hello");
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


    @RequestMapping("/toLogin")
    public String toLogin() {
        return "login";
    }

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

    @RequestMapping("/noauth")
    @ResponseBody
    public String noauth() {
        return "這是未經授權的用戶";
    }

}
