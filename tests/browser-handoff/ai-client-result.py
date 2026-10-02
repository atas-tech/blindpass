# SPDX-License-Identifier: AGPL-3.0-only
import json
def artifact_count(name, text):
 try:
  if not isinstance(text,str) or len(text.encode())>2*1024*1024:raise ValueError()
  if name=='claude':
   result=json.loads(text)
   if result.get('type')!='result':raise ValueError()
   answer=result['result']
  elif name=='codex':
   answers=[event['item']['text'] for line in text.splitlines() if line.strip()
    for event in [json.loads(line)] if event.get('type')=='item.completed'
    and event.get('item',{}).get('type')=='agent_message']
   answer=answers[-1]
  else:raise ValueError()
  value=json.loads(answer)
  if not isinstance(value,dict) or set(value)!= {'artifacts'} or type(value['artifacts']) is not int or not 0<=value['artifacts']<=1000000:raise ValueError()
  return value['artifacts']
 except (ValueError,TypeError,KeyError,IndexError,AttributeError):raise ValueError('client_result_invalid') from None

# Fixed-vocabulary classification of a final answer that did not parse, for diagnostics. It returns one of
# a closed set of names and never any part of the text, so it is safe to print.
def answer_shape(name,text):
 try:
  if not isinstance(text,str) or len(text.encode())>2*1024*1024:return 'envelope'
  if name=='claude':
   result=json.loads(text)
   if not isinstance(result,dict) or result.get('type')!='result' or not isinstance(result.get('result'),str):return 'envelope'
   answer=result['result']
  elif name=='codex':
   answers=[event['item']['text'] for line in text.splitlines() if line.strip()
    for event in [json.loads(line)] if event.get('type')=='item.completed'
    and event.get('item',{}).get('type')=='agent_message']
   answer=answers[-1]
   if not isinstance(answer,str):return 'envelope'
  else:return 'envelope'
 except (ValueError,TypeError,KeyError,IndexError,AttributeError):return 'envelope'
 if not answer.strip():return 'empty'
 if answer.lstrip().startswith('```'):return 'fenced'
 try:value=json.loads(answer)
 except ValueError:return 'not_json'
 if not isinstance(value,dict):return 'json_not_object'
 if set(value)!={'artifacts'}:return 'json_keys'
 if type(value['artifacts']) is not int or not 0<=value['artifacts']<=1000000:return 'json_value'
 return 'valid'
