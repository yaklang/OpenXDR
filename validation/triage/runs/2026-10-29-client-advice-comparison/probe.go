// 本轮固定答案对照探针，不属于生产入口。
package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "time"
 "openxdr/server/internal/triage"
 "openxdr/server/internal/triageeval"
)

type sample struct { ID string `json:"id"`; Variant string `json:"variant"`; Answer json.RawMessage `json:"answer"`; Expected string `json:"expected_actions"` }
func digest(data []byte) string {sum:=sha256.Sum256(data);return hex.EncodeToString(sum[:])}
func main(){
 cases,err:=triageeval.Load("/tmp/openxdr-client-advice-cases.json");if err!=nil {panic("invalid cases")}
 var target triageeval.Case
 for _,c:=range cases {if c.ID=="mixed_clients" {target=c}}
 if target.ID=="" {panic("missing case")}
 data,err:=os.ReadFile("/tmp/openxdr-client-advice-samples.json");if err!=nil {panic("missing samples")}
 var samples []sample
 if json.Unmarshal(data,&samples)!=nil || len(samples)!=4 {panic("invalid samples")}
 f,err:=os.OpenFile("/tmp/openxdr-client-advice-report.jsonl",os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil {panic("cannot create report")};defer f.Close()
 enc:=json.NewEncoder(f)
 write:=func(v any){if enc.Encode(v)!=nil || f.Sync()!=nil {panic("report write failed")}}
 llm:=triage.NewLLM(os.Getenv("AI_BASE_URL"),os.Getenv("AI_MODEL"),os.Getenv("AI_API_KEY"),120*time.Second)
 llm.MaxTokens=8192
 write(map[string]any{"kind":"metadata","started_at":time.Now().UTC(),"scope":"fixed_answer_advice_comparison","model":llm.Model,"judge_no_thinking":llm.NoThinking,"judge_max_tokens":llm.MaxTokens,"judge_prompt_sha256":triageeval.PromptHash(),"action_prompt_sha256":triageeval.ActionPromptHash(),"samples_sha256":digest(data),"repeats":2,"independent_human_review":"pending"})
 controls,comparisons,failed:=0,0,0
 assess:=func(answer json.RawMessage)(triageeval.Assessment,[]triageeval.ReviewAttempt,error,int,int){
  in,out:=0,0
  llm.OnUsage=func(_ string,a,b int){in+=a;out+=b}
  ctx,cancel:=context.WithTimeout(context.Background(),150*time.Second);defer cancel()
  a,attempts,err:=triageeval.JudgeDetailed(ctx,llm,target,answer)
  return a,attempts,err,in,out
 }
 for _,control:=range target.Calibration(){
  a,attempts,err,in,out:=assess(control.Answer)
  matched:=err==nil && control.Matches(a)
  row:=map[string]any{"kind":"calibration","control":control.ID,"expected_reject":control.Reject,"answer":control.Answer,"assessment":a,"judge_attempts":attempts,"matched":matched,"input_tokens":in,"output_tokens":out}
  if err!=nil {row["error_detail"]=triageeval.Diagnose(err)}
  write(row);controls++;if !matched {failed++}
  fmt.Println("calibration",control.ID,matched)
 }
 for repeat:=1;repeat<=2;repeat++ {for _,s:=range samples {
  a,attempts,err,in,out:=assess(s.Answer)
  matched:=err==nil && a["actions"].Status==s.Expected
  row:=map[string]any{"kind":"comparison","id":s.ID,"variant":s.Variant,"repeat":repeat,"expected_actions":s.Expected,"answer":s.Answer,"assessment":a,"judge_attempts":attempts,"actions_matched":matched,"input_tokens":in,"output_tokens":out}
  if err!=nil {row["error_detail"]=triageeval.Diagnose(err)}
  write(row);comparisons++;if !matched {failed++}
  fmt.Println("comparison",s.ID,s.Variant,repeat,matched)
 }}
 write(map[string]any{"kind":"summary","complete":true,"finished_at":time.Now().UTC(),"controls":controls,"comparisons":comparisons,"unmatched_checks":failed,"scope":"fixed_answer_advice_comparison","product_semantic_gate":"not_evaluated"})
 if failed>0 {os.Exit(1)}
}
