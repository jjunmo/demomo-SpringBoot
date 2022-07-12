package kr.co.promisemomo.module.promise.controller;

import kr.co.promisemomo.module.member.entity.Member;
import kr.co.promisemomo.module.member.service.MemberService;
import kr.co.promisemomo.module.promise.dto.request.PromiseCreateRequest;
import kr.co.promisemomo.module.promise.service.PromiseService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/promise")
public class PromiseRestController {

    public final PromiseService promiseService;
    public final MemberService memberService;

    @PostMapping("/member")
    public HttpEntity<Object> addPromise(@RequestParam("member_id") Long memberId, @RequestBody PromiseCreateRequest promiseCreateRequest){

        Optional<Member> memberOptional = memberService.getMember(memberId);
        if (memberOptional.isEmpty()) {
            return ResponseEntity.badRequest().body("로그인이 필요합니다.");
        }
        // Validation Check
        String validationResult = promiseService.validationPromise(promiseCreateRequest);
        if (!validationResult.equals("OK") ) {
            return ResponseEntity.badRequest().body(validationResult);
        }
        return ResponseEntity.ok(promiseService.addPromise(memberOptional.get(), promiseCreateRequest));
    }

    @GetMapping("/member")
    public HttpEntity<Object> getPromises(@RequestParam("member_id") Long memberId){
        Optional<Member> memberOptional = memberService.getMember(memberId);
        if (memberOptional.isEmpty()) {
            return ResponseEntity.badRequest().body("로그인이 필요합니다.");
        }

        return ResponseEntity.ok().body(promiseService.getParticipatePromises(memberId));
    }



    
    
}
