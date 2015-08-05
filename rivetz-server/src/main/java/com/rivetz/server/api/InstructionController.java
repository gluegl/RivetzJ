package com.rivetz.server.api;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//import com.rivetz.lib.Instruction;

/**
 *
 */
@RestController
public class InstructionController {

    @RequestMapping("/hello")
    public String index() {
        return "Greetings from Rivet-Server!";
    }

//    @RequestMapping("/instruction")
//    public Instruction instruction() {
//        Instruction instruction = new Instruction();
//        return instruction;
//    }

}
