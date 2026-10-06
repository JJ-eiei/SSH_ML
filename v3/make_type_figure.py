"""make_type_figure.py -- slide figure: stage-2 attack-type confusion matrix on the
OOD set (black/yellow deck theme). Reads v3/type_model_eval.json written by
train_type_model.py.  Run: python v3/make_type_figure.py"""
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
import json, numpy as np, matplotlib
matplotlib.use('Agg'); import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
r=json.load(open(ROOT/'v3'/'type_model_eval.json'))
cm=r['ood']['confusion_matrix']; labels=cm['labels']; M=np.array(cm['matrix'])
NAME={"burst_bruteforce":"Burst brute force","focused_bruteforce":"Focused brute force","large_dictionary_scanner":"Dictionary scanner","low_and_slow":"Low-and-slow","persistent_multiday_attacker":"Persistent multi-day","coordinated_botnet_spike":"Botnet spike","password_spray":"Password spraying","credential_stuffing":"Credential stuffing"}
MITRE={"burst_bruteforce":"T1110.001","focused_bruteforce":"T1110.001","large_dictionary_scanner":"T1110.001","low_and_slow":"T1110.001","persistent_multiday_attacker":"T1110.001","coordinated_botnet_spike":"T1110","password_spray":"T1110.003","credential_stuffing":"T1110.004"}
order=list(NAME)
idx=[labels.index(k) for k in order]; M=M[np.ix_(idx,idx)]; R=M/M.sum(1,keepdims=True)
BG='#0b0b0d'; INK='#f2f2f2'; MUTED='#9a9aa0'; YEL='#FFC61A'
cmap=LinearSegmentedColormap.from_list('y',['#17171b','#3a3010','#8a6a0a',YEL])
fig,ax=plt.subplots(figsize=(16,9),dpi=120); fig.patch.set_facecolor(BG); ax.set_facecolor(BG)
ax.imshow(R,cmap=cmap,vmin=0,vmax=1); n=len(order)
for i in range(n):
  for j in range(n):
    v=M[i,j]
    if v==0: ax.text(j,i,'·',ha='center',va='center',color='#4a4a50',fontsize=16); continue
    ax.text(j,i,f'{v}',ha='center',va='center',fontsize=17,fontweight='bold',color='#111' if R[i,j]>0.55 else INK)
for k in range(n+1): ax.axhline(k-0.5,color=BG,lw=3); ax.axvline(k-0.5,color=BG,lw=3)
ax.set_yticks(range(n)); ax.set_yticklabels([f'{NAME[k]}  ({MITRE[k]})' for k in order],color=INK,fontsize=12.5)
ax.set_xticks(range(n)); ax.set_xticklabels([NAME[k] for k in order],color=INK,fontsize=12.5,rotation=30,ha='right')
ax.tick_params(length=0); [s.set_visible(False) for s in ax.spines.values()]
ax.set_ylabel('True type',color=MUTED,fontsize=13); ax.set_xlabel('Predicted type',color=MUTED,fontsize=13)
o=r['ood']
fig.text(0.04,0.95,'Attack-type classification (stage 2) — OOD set',color=YEL,fontsize=24,fontweight='bold')
fig.text(0.04,0.905,f"n = {o['n']:,} attack sessions  ·  accuracy {o['accuracy']*100:.1f}%  ·  macro F1 {o['macro_f1']:.3f}  ·  synthetic data (seed 777, 45 days)  ·  cell colour = share of true row",color=MUTED,fontsize=12.5)
plt.subplots_adjust(left=0.22,right=0.98,top=0.86,bottom=0.21)
out=ROOT/'canva_upload'/'attack_type_confusion_ood.png'; out.parent.mkdir(exist_ok=True); fig.savefig(out,facecolor=BG); print('saved',out)
