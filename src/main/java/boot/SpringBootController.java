package boot;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.concurrent.atomic.AtomicLong;

@Controller
public class SpringBootController {

    private final AtomicLong counter = new AtomicLong();

    @GetMapping("/boot")
    @ResponseBody
    public Test sayHello(@RequestParam(name= "boot", required=false, defaultValue="boot.Test") String test) {
        return new Test(counter.incrementAndGet(), test);
    }

}
