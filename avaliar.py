#!/usr/bin/env python3
"""lm-evaluation-harness + MLX; measured evidence, no invented intelligence grade."""
import argparse, datetime, hashlib, importlib.metadata, inspect, json, math, os
import platform, shutil, subprocess, sys, time, traceback, uuid
from pathlib import Path
from memoria import POLICY, MemoryReader, MemorySupervisor, apply_mlx_limits, exclusive_run, kill_worker, breach
CREDITS={
 'Autoria e desenvolvimento do modelo e dos pesos':'Paulo Ricardo de Leão',
 'Concepção do projeto':'Paulo Ricardo de Leão e Raphaela Cerveski',
 'Organização do projeto':'Regenera Corporate',
}
PLAN=[('hellaswag',0,False),('arc_challenge',0,False),('belebele_por_Latn',0,False),('gsm8k_cot',8,True),('ifeval',0,True)]
SKIP={'.git','.cache','__pycache__','evidencias','node_modules'}
def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def convert(x):
 import base64, enum, functools
 if isinstance(x,enum.Enum):
  return {'__type__':'enum','class':type(x).__module__+'.'+type(x).__qualname__,'name':x.name,'value':x.value}
 if isinstance(x,(datetime.datetime,datetime.date,datetime.time)):
  return {'__type__':type(x).__name__,'iso':x.isoformat()}
 if isinstance(x,(bytes,bytearray)):
  return {'__type__':'bytes','encoding':'base64','data':base64.b64encode(x).decode('ascii')}
 if isinstance(x,Path): return str(x)
 if isinstance(x,(set,frozenset)):
  values=sorted(x,key=lambda v:json.dumps(v,default=convert,sort_keys=True))
  return {'__type__':type(x).__name__,'values':values}
 if isinstance(x,functools.partial):
  return {'__type__':'partial','function':convert(x.func),'args':x.args,'keywords':x.keywords}
 if callable(x):
  record={'__type__':'callable','module':getattr(x,'__module__',type(x).__module__),
          'qualname':getattr(x,'__qualname__',type(x).__qualname__)}
  try:
   record['source_sha256']=hashlib.sha256(inspect.getsource(x).encode('utf-8')).hexdigest()
  except (TypeError,OSError): record['source_sha256']=None
  return record
 if hasattr(x,'tolist'): return x.tolist()
 if hasattr(x,'item'): return x.item()
 raise TypeError('Tipo não serializável: '+str(type(x)))
def write(p,x):
 # Serialize completely before opening the destination; never leave truncated JSON.
 payload=json.dumps(x,ensure_ascii=False,indent=2,default=convert)+'\n'
 temp=p.with_name(p.name+'.tmp-'+uuid.uuid4().hex)
 try:
  with temp.open('x',encoding='utf-8') as f:
   f.write(payload); f.flush(); os.fsync(f.fileno())
  os.replace(temp,p)
 finally:
  if temp.exists(): temp.unlink()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''): h.update(b)
 return h.hexdigest()
def walk(root,exclude=False):
 for current,dirs,files in os.walk(root,followlinks=False):
  dirs[:]=sorted(d for d in dirs if not (exclude and (d in SKIP or d.startswith('.venv'))))
  for d in dirs:
   if (Path(current)/d).is_symlink(): raise RuntimeError('Diretório simbólico não suportado: '+str(Path(current)/d))
  for name in sorted(files):
   if exclude and name=='.DS_Store': continue
   p=Path(current)/name
   if p.is_symlink(): raise RuntimeError('Link simbólico não suportado: '+str(p))
   yield p

def inventory(root,exclude=False):
 rows=[]
 for p in walk(root,exclude):
  s=p.stat()
  if exclude: print('SHA-256',p.relative_to(root),flush=True)
  digest=sha(p); e=p.stat()
  if (s.st_size,s.st_mtime_ns)!=(e.st_size,e.st_mtime_ns): raise RuntimeError('Arquivo mudou durante hash: '+str(p))
  rows.append({'path':p.relative_to(root).as_posix(),'bytes':s.st_size,'sha256':digest})
 return sorted(rows,key=lambda r:r['path'])

def discover(root):
 candidates=[]
 for p in walk(root,True):
  if p.name=='config.json' and any(p.parent.glob('*.safetensors')): candidates.append(p.parent.resolve())
 candidates=sorted(set(candidates))
 if len(candidates)!=1:
  raise RuntimeError('Esperada UMA pasta com config.json e pesos .safetensors dentro do local informado. Encontradas: '+str([str(p) for p in candidates])+'. Informe --model com o caminho correto; nenhum outro modelo foi escolhido.')
 return candidates[0]

def first_stop(text,stops):
 valid=[s for s in stops if isinstance(s,str) and s]
 hits=[(text.find(s),s) for s in valid if text.find(s)>=0]
 return min(hits,key=lambda x:x[0]) if hits else (None,None)

def effective_generation_limit(options,backend_default):
 value=options.get('max_gen_toks')
 return int(value) if value is not None else int(backend_default)

def consume_generation(stream,stops):
 raw=''; last=None; offset=None; hit=None
 try:
  for item in stream:
   raw+=item.text; last=item
   offset,hit=first_stop(raw,stops)
   print(item.text,end='',flush=True)
   if hit is not None: break
 finally:
  close=getattr(stream,'close',None)
  if close is not None: close()
 return raw,raw[:offset] if hit is not None else raw,last,offset,hit

def extract(raw,prompt):
 # A chat template may have already opened <think> in the assistant prefix.
 opened=('<think>' in raw or prompt.rfind('<think>')>prompt.rfind('</think>'))
 if '</think>' in raw:
  reasoning,final=raw.rsplit('</think>',1)
  if '<think>' in reasoning: reasoning=reasoning.split('<think>',1)[1]
  if '<think>' in final: return reasoning,'','MALFORMED_THINK'
  return reasoning,final.strip(),'CLOSED_THINK'
 if opened: return raw,'','UNCLOSED_THINK'
 return '',raw.strip(),'NO_THINK_TAG'

def verify(root):
 rows=[r for r in inventory(root) if r['path'] not in ('MANIFEST.json','MANIFEST.sha256')]
 if rows!=json.loads((root/'MANIFEST.json').read_text()): raise RuntimeError('FAIL: arquivos alterados, adicionais ou ausentes')
 if sha(root/'MANIFEST.json')!=(root/'MANIFEST.sha256').read_text().strip(): raise RuntimeError('FAIL: hash do manifesto')
 print('INTEGRIDADE INTERNA VERIFICADA. Não equivale a assinatura, autoria ou data certificada.')

def validate_result(result,task):
 if not result or task not in result.get('results',{}): raise RuntimeError('Tarefa sem resultado: '+task)
 if not result.get('samples',{}).get(task): raise RuntimeError('Sem amostras: '+task)
 values=[v for k,v in result['results'][task].items() if k!='alias' and 'stderr' not in k and isinstance(v,(int,float))]
 if not values or not all(math.isfinite(v) for v in values): raise RuntimeError('Métricas inválidas: '+task)

def worker(model,out,mode,max_tokens):
 import mlx.core as mx
 write(out/'limites_mlx.json',apply_mlx_limits(mx))
 import lm_eval, mlx_lm
 from mlx_lm.evaluate import MLXLM
 from mlx_lm import stream_generate
 from mlx_lm.sample_utils import make_sampler
 mx.random.seed(42)
 class RecordedMLX(MLXLM):
  current_task=''
  def apply_chat_template(self,chat_history,add_generation_prompt=True):
   return self.tokenizer.apply_chat_template(chat_history,tokenize=False,
     add_generation_prompt=add_generation_prompt,enable_thinking=True)
  def generate_until(self,requests):
   answers=[]
   for index,req in enumerate(requests):
    prompt,opts=req.args; started=time.perf_counter(); raw=''; last=None
    stops=opts.get('until',[])
    if isinstance(stops,str): stops=[stops]
    stops=[x for x in stops if isinstance(x,str) and x]
    # Chat control markers end an assistant turn even when a task omits until.
    if '<|im_start|>' in prompt:
     stops=list(dict.fromkeys(stops+['<|im_end|>','<|im_start|>','<|endoftext|>']))
    # Match MLX-LM's official policy: task max_gen_toks wins; otherwise use
    # the backend default supplied by this collector (8192 by default).
    task_max=opts.get('max_gen_toks')
    effective_max_tokens=effective_generation_limit(opts,max_tokens)
    print(f'\n[{self.current_task} {index+1}/{len(requests)}] GERANDO AO VIVO '
          f'(max_gen_toks={effective_max_tokens}, until={stops})',flush=True)
    # Explicit tokenization: the harness has already applied the chat template.
    tokens=self.tokenizer.encode(prompt,add_special_tokens=False)
    stream=stream_generate(self._model,self.tokenizer,tokens,max_tokens=effective_max_tokens,
      sampler=make_sampler(temp=0.0),prefill_step_size=256)
    raw,scoring_output,last,stop_offset,stop_hit=consume_generation(stream,stops)
    print(flush=True)
    reasoning,final,state=extract(scoring_output,prompt)
    scored=final
    finish_reason='task_until' if stop_hit is not None else getattr(last,'finish_reason',None)
    record={'task':self.current_task,'request_index':index,'doc_id':getattr(req,'doc_id',None),
     'prompt':prompt,'raw_output':raw,'reasoning_text':reasoning,'final_answer':final,
     'scored_answer':scored,'parsing':state,'task_options':opts,'effective_max_tokens':effective_max_tokens,
     'task_max_gen_toks':task_max,'until':stops,'stop_reason':stop_hit,'stop_offset':stop_offset,
     'seconds':time.perf_counter()-started,'finish_reason':finish_reason,
     'generation_tokens':getattr(last,'generation_tokens',None),'generation_tps':getattr(last,'generation_tps',None),
     'last_token_id':getattr(last,'token',None),
     'prompt_tokens':getattr(last,'prompt_tokens',None),'peak_memory_gb':getattr(last,'peak_memory',None),
     'mlx_active_bytes':mx.get_active_memory(),'mlx_cache_bytes':mx.get_cache_memory(),
     'prefill_step_size':256}
    with (out/'geracoes_brutas.jsonl').open('a') as f: f.write(json.dumps(record,ensure_ascii=False,default=convert)+'\n'); f.flush(); os.fsync(f.fileno())
    answers.append(scored)
    mx.clear_cache()
   return answers
  def _process_prompt(self,prompt,step_size=256):
   return super()._process_prompt(prompt,step_size=256)
  def _score_fn(self,inputs,cache=None,step_size=256):
   return super()._score_fn(inputs,cache=cache,step_size=256)
 lm=RecordedMLX(str(model),batch_size=1,use_chat_template=False,trust_remote_code=False)
 eos_ids=sorted(int(x) for x in lm.tokenizer.eos_token_ids)
 marker_id=lm.tokenizer.encode('<|im_end|>',add_special_tokens=False)
 if len(marker_id)!=1 or marker_id[0] not in eos_ids:
  raise RuntimeError('EOS efetivo não inclui <|im_end|>. Execute corrigir_parada.py antes de avaliar.')
 write(out/'parada_efetiva.json',{'eos_token_ids':eos_ids,'im_end_token_id':marker_id[0],
  'chat_template_sha256':hashlib.sha256(lm.tokenizer.chat_template.encode()).hexdigest()})
 if not lm.tokenizer.chat_template: raise RuntimeError('Tokenizer sem chat_template: não é possível avaliar o modo de raciocínio definido')
 source=Path(inspect.getfile(type(lm._model)))
 write(out/'arquitetura_carregada.json',{'class':str(type(lm._model)),'path':str(source),'sha256':sha(source)})
 (out/'arquitetura_carregada.py.txt').write_bytes(source.read_bytes())
 # Exercise the loaded model under the same memory supervisor BEFORE benchmarks.
 # These checks validate execution and termination, not general intelligence.
 if mode=='smoke':
  from types import SimpleNamespace
  lm.current_task='preflight_real'; lm.use_chat_template=True
  checks=[]
  for text in ('Responda somente a palavra OK, sem explicações.',
               'Quanto é 2 + 2? Responda somente o número.'):
   prompt=lm.apply_chat_template([{'role':'user','content':text}])
   req=SimpleNamespace(args=(prompt,{'until':['<|im_end|>','<|im_start|>','<|endoftext|>'],
                                   'max_gen_toks':512}),doc_id=len(checks))
   answer=lm.generate_until([req])[0]
   record=json.loads((out/'geracoes_brutas.jsonl').read_text().splitlines()[-1])
   passed=bool(answer.strip()) and record['finish_reason'] in ('stop','task_until')
   checks.append({'prompt':text,'answer':answer,'finish_reason':record['finish_reason'],
                  'parsing':record['parsing'],'execution_and_stop_verified':passed})
   write(out/'preflight_real.json',{'checks':checks,'all_passed':all(c['execution_and_stop_verified'] for c in checks)})
   if not passed:
    raise RuntimeError('Teste real prévio não confirmou resposta final e parada em até 512 tokens. '
                       'Benchmark não iniciado; veja preflight_real.json e geracoes_brutas.jsonl.')
  print('TESTE REAL PRÉVIO: 2 respostas concluídas; parada verificada; iniciando smoke.',flush=True)
 # Archive effective implementation (including local regenera adapter) and benchmark YAMLs.
 for label,module in [('mlx_lm',mlx_lm),('lm_eval',lm_eval)]:
  src=Path(module.__file__).parent
  for p in src.rglob('*'):
   if p.is_file() and p.suffix in ('.py','.yaml','.yml','.jinja'):
    dst=out/'fontes_avaliador'/label/p.relative_to(src); dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,dst)
 for task,shots,chat in PLAN:
  lm.current_task=task; lm.use_chat_template=chat
  result=lm_eval.simple_evaluate(model=lm,tasks=[task],num_fewshot=shots,limit=3 if mode=='smoke' else None,
   apply_chat_template=chat,fewshot_as_multiturn=False,log_samples=True,
   random_seed=42,numpy_random_seed=42,torch_random_seed=42,fewshot_random_seed=42)
  validate_result(result,task)
  write(out/(task+'_metricas.json'),result['results'])
  write(out/(task+'.json'),result)
  print(json.dumps(result['results'],indent=2),flush=True)
  mx.clear_cache()

def report(out,status):
 lines=['# Regenera Corporate — Registro de avaliação','']
 lines += [f'**{k}:** {v}  ' for k,v in CREDITS.items()]
 lines+=['','Créditos fornecidos pelo responsável; a avaliação não constitui perícia de autoria.','',f"Estado: **{status['state']}**",'', '| Tarefa | Métrica | Valor |','|---|---|---|']
 for task,_,_ in PLAN:
  p=out/(task+'.json')
  if p.exists():
   for k,v in json.loads(p.read_text())['results'][task].items():
    if k!='alias': lines.append(f'| {task} | {k} | {v} |')
 p=out/'geracoes_brutas.jsonl'
 if p.exists():
  records=[]; incomplete=0
  for line in p.read_text(errors='replace').splitlines():
   if not line.strip(): continue
   try: records.append(json.loads(line))
   except json.JSONDecodeError: incomplete+=1
  lines+=['','## Saídas generativas observadas',f'Total: {len(records)}']
  if incomplete: lines.append(f'Registros interrompidos/incompletos preservados no JSONL: {incomplete}.')
  for state in ['CLOSED_THINK','UNCLOSED_THINK','MALFORMED_THINK','NO_THINK_TAG']:
   lines.append(f'- {state}: {sum(r["parsing"]==state for r in records)}')
  lines.append(f'- Finalizações por limite de tokens: {sum(r["finish_reason"]=="length" for r in records)}')
 lines+=['','## Escopo','SMOKE: apenas 3 exemplos por tarefa, sem conclusão sobre capacidade geral. FULL: conjuntos completos das tarefas selecionadas.',
 'Perfil: compreensão PT (Belebele), senso comum (HellaSwag), ciências (ARC Challenge), matemática (GSM8K CoT), seguimento de instruções (IFEval).',
 'Não se atribui QI, consciência ou categoria universal de inteligência. Texto <think> é uma saída observável, não prova de um processo interno fiel.',
 'Geração: template do próprio modelo, inclusive seu sistema padrão, com enable_thinking=True; suporte efetivo depende do template. A presença/ausência das tags é registrada.',
 'GSM8K usa 8 exemplos; demais tarefas zero-shot. Tarefas de múltipla escolha usam loglikelihood sem chat template e não medem pensamento gerado.',
 'Geração respeita generation_kwargs do LM Evaluation Harness. max_gen_toks da tarefa tem precedência; quando ausente, usa o padrão do backend. Stops definidos em until interrompem o streaming na primeira ocorrência e são registrados por amostra. Não há pós-corte destinado a alterar pontuação.',
 'Pensamento sem fechamento recebe resposta vazia para pontuação; não é excluído do denominador. Amostras que atingem limite permanecem registradas.',
 'Resultados sujeitos a contaminação de treino não auditada, efeitos de quantização e implementação do backend. Não é avaliação de segurança ou produção.',
 '32B, autoria, treinamento do zero e licenças não são certificados por este coletor. Assinatura digital, carimbo do tempo e validação independente permanecem externos.',
 'Data/hora são do relógio local. Hash sem assinatura/âncora externa pode ser recalculado por quem alterar o dossiê.']
 lines+=['','## Memória',
 'Orçamento: 50 GB decimais. MLX: 42 GB orientativos, cache 256 MB, wired no máximo 42 GB e dentro do limite do dispositivo.',
 'O controlador monitora a soma conservadora de max(RSS, phys_footprint) por processo, incluindo seus filhos. Encerra seu worker ao detectar 48 GB ou menos de 8 GB disponíveis no sistema.',
 'Amostragem solicitada a cada 100 ms: não é quota rígida do macOS e não garante ausência de picos entre amostras. A pressão causada por outros aplicativos também pode provocar interrupção.',
 'Lote 1; prefill e blocos de loglikelihood de 256 tokens. Sem redução silenciosa do conjunto de tarefas ou da quantidade de respostas.']
 if (out/'memoria_resumo.json').exists():
  memory=json.loads((out/'memoria_resumo.json').read_text())
  lines.append('Maior consumo AMOSTRADO da avaliação: '+str(memory['sampled_peak_bytes']/1e9)+' GB.')
  lines.append('Motivo de interrupção por memória: '+str(memory['reason']))
 (out/'RELATORIO.md').write_text('\n'.join(lines)+'\n')

def run(a):
 root=Path(a.root).expanduser().resolve()
 if not root.is_dir(): raise RuntimeError('Local informado não existe: '+str(root))
 out=root/'evidencias'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+a.mode+'_'+uuid.uuid4().hex[:8]); out.mkdir(parents=True)
 status={'state':'IN_PROGRESS','started_utc_local_clock':utc(),'mode':a.mode}
 write(out/'status.json',status); write(out/'creditos.json',CREDITS); shutil.copyfile(__file__,out/'avaliar.py')
 shutil.copyfile(Path(__file__).with_name('memoria.py'),out/'memoria.py')
 try:
  if platform.system()!='Darwin' or platform.machine()!='arm64': raise RuntimeError('Requer Python arm64 em Mac Apple Silicon')
  # Controller never loads MLX or the model. Worker imports occur under supervision.
  reader=MemoryReader()
  preflight=reader.snapshot(os.getpid()); write(out/'memoria_preflight.json',preflight)
  if breach(preflight): raise RuntimeError('Memória disponível insuficiente antes da carga.')
  for package in ('mlx','mlx-lm','lm_eval','psutil'): importlib.metadata.version(package)
  model=Path(a.model).expanduser().resolve() if a.model else discover(root)
  if model!=root and root not in model.parents: raise RuntimeError('--model deve permanecer dentro do local autorizado --root')
  config=json.loads((model/'config.json').read_text()); write(out/'config_modelo.json',config)
  if not any(model.glob('*.safetensors')): raise RuntimeError('Sem pesos .safetensors')
  write(out/'versao_coletor.json',{'version':'2.6.3-50GB','training_reported_by_user':True,'prior_evidence_preserved':True,'lm_eval_version':importlib.metadata.version('lm_eval'),'mlx_lm_version':importlib.metadata.version('mlx_lm'),'lm_eval_install_pin':'d6de81643928d653435c431bae19945d41d32520'})
  git_info={}
  for label,git_args in [('head',['rev-parse','HEAD']),('status',['status','--porcelain']),('root',['rev-parse','--show-toplevel'])]:
   res=subprocess.run(['git','-C',str(model),*git_args],capture_output=True,text=True)
   git_info[label]={'exit_code':res.returncode,'stdout':res.stdout,'stderr':res.stderr}
  write(out/'git_modelo.json',git_info)
  write(out/'ambiente.json',{'python':sys.executable,'version':sys.version,'platform':platform.platform(),'model':str(model)})
  with (out/'dependencias.txt').open('w') as f: subprocess.run([sys.executable,'-m','pip','freeze','--all'],stdout=f,stderr=subprocess.STDOUT,check=True)
  write(out/'protocolo.json',{'credits':CREDITS,'plan':PLAN,'seed':42,'batch':1,'prefill_step_size':256,'memory_policy':POLICY,'limit':3 if a.mode=='smoke' else None,'backend_default_max_gen_toks':a.max_tokens,'thinking_requested':True,'raw_saved':True,'model':str(model),'hash_exclusions':sorted(SKIP)+['.venv*','.DS_Store'],'identity_certified':False,'trusted_timestamp':False})
  before=inventory(model,True); write(out/'modelo_antes.json',before)
  cmd=[sys.executable,'-u',str(Path(__file__).resolve()),'_worker','--model',str(model),'--root',str(out),'--mode',a.mode,'--max-tokens',str(a.max_tokens)]; write(out/'comando.json',cmd)
  with (out/'execucao.log').open('w') as log:
   proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,start_new_session=True)
   monitor=MemorySupervisor(proc,out,reader=reader)
   try:
    monitor.start()
    # Character streaming preserves live generation without waiting for newline.
    while True:
     char=proc.stdout.read(1)
     if not char: break
     print(char,end='',flush=True); log.write(char); log.flush()
    rc=proc.wait()
   except BaseException:
    kill_worker(proc); proc.wait(); raise
   finally:
    memory=monitor.close()
  if memory['reason']:
   status['state']='MEMORY_LIMIT_ABORT'
   raise MemoryError('Proteção de memória: '+memory['reason'])
  status['exit_code']=rc
  after=inventory(model,True); write(out/'modelo_depois.json',after)
  if before!=after: raise RuntimeError('Arquivos do modelo mudaram durante avaliação')
  if rc: raise RuntimeError('Avaliador retornou erro: consulte execucao.log')
  for task,_,_ in PLAN: validate_result(json.loads((out/(task+'.json')).read_text()),task)
  status['state']='SMOKE_VERIFIED' if a.mode=='smoke' else 'EVALUATION_RECORDED'
 except BaseException as exc:
  state='MEMORY_LIMIT_ABORT' if status['state']=='MEMORY_LIMIT_ABORT' else ('INTERRUPTED' if isinstance(exc,KeyboardInterrupt) else 'FAILED')
  status.update(state=state,error=str(exc)); (out/'falha.txt').write_text(traceback.format_exc()); print(traceback.format_exc(),flush=True)
 finally:
  status['ended_utc_local_clock']=utc(); write(out/'status.json',status); report(out,status)
  write(out/'MANIFEST.json',inventory(out)); (out/'MANIFEST.sha256').write_text(sha(out/'MANIFEST.json')+'\n')
  verify(out); print('ESTADO:',status['state'],'\nDOSSIÊ:',out,flush=True)
 return 0 if status['state'] in ('SMOKE_VERIFIED','EVALUATION_RECORDED') else 1

def main():
 p=argparse.ArgumentParser(); p.add_argument('action',choices=['run','verify','_worker']); p.add_argument('--root',default='/Users/enterprise/Desktop/32B-REGENERA'); p.add_argument('--model'); p.add_argument('--mode',choices=['smoke','full'],default='smoke'); p.add_argument('--max-tokens',type=int,default=8192); a=p.parse_args()
 if a.max_tokens<1: p.error('--max-tokens deve ser positivo')
 if a.action=='verify': verify(Path(a.root)); return 0
 if a.action=='_worker': worker(Path(a.model),Path(a.root),a.mode,a.max_tokens); return 0
 with exclusive_run(Path(a.root).expanduser().resolve()): return run(a)
if __name__=='__main__': sys.exit(main())
