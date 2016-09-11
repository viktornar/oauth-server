package lt.geostream.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/admin")
public class Admin {
    @ResponseBody
    @RequestMapping(method = RequestMethod.GET)
    String get(){
        return "hello from admin";
    }
}