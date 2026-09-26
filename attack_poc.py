"""PoC known-plaintext attack terhadap skenario Vigenere+Hill+Transposisi.
Letakkan di folder yang sama dengan algorithms.py lalu jalankan: python attack_poc.py
"""
import itertools, time, random
import algorithms as A, transposition, hill, sample_data
M=26
def idx(s): return [ord(c)-65 for c in s]
def inv3(Mx):
    try: return hill.matrix_inverse(Mx, M)
    except ValueError: return None
def matmul(X,Y): return [[sum(X[i][k]*Y[k][j] for k in range(3))%M for j in range(3)] for i in range(3)]
def mv(X,v): return [sum(X[i][k]*v[k] for k in range(3))%M for i in range(3)]

def affine_attack(p, y, period):
    """y_t = K p_t + b_(t mod period). Return (K,b) consistent with all blocks or None."""
    nb=len(p)//3
    P=[p[3*t:3*t+3] for t in range(nb)]; Y=[y[3*t:3*t+3] for t in range(nb)]
    # differences within same class
    diffs=[]
    for j in range(period):
        ts=[t for t in range(nb) if t%period==j]
        for a,b in zip(ts,ts[1:]):
            diffs.append(([(P[a][i]-P[b][i])%M for i in range(3)],[(Y[a][i]-Y[b][i])%M for i in range(3)]))
            if len(diffs)>60: break
    for trip in itertools.combinations(range(min(len(diffs),20)),3):
        Dp=[[diffs[k][0][i] for k in trip] for i in range(3)]
        Dy=[[diffs[k][1][i] for k in trip] for i in range(3)]
        Di=inv3(Dp)
        if Di is None: continue
        K=matmul(Dy,Di)
        b=[[(Y[j][i]-mv(K,P[j])[i])%M for i in range(3)] for j in range(period)]
        if all((mv(K,P[t])[i]+b[t%period][i]-Y[t][i])%M==0 for t in range(nb) for i in range(3)):
            return K,b
        return None  # first invertible triple decides for this candidate
    return None

pt=sample_data.corpus_normal()[:1000]
pt=pt[:len(pt)-len(pt)%3]  # 999, avoid padding for simplicity
sc=A.SCENARIOS[6]  # V+H+T
body=sc.cipher_body(pt)
t0=time.perf_counter(); found=None; tried=0
for perm in itertools.permutations("ABCDEF"):
    tried+=1
    y=idx(transposition.decrypt(body,"".join(perm)))
    for period in range(1,11):
        r=affine_attack(idx(pt),y,period)
        if r: found=("".join(perm),period,r); break
    if found: break
dt=time.perf_counter()-t0
print("V+H+T KPA: tried perms",tried,"time %.2fs"%dt)
perm,period,(K,b)=found
print("perm",perm,"period",period,"K",K,"true",A.HILL_MATRIX)
Kinv=hill.matrix_inverse(K,M)
vig=[mv(Kinv,bj) for bj in b]
# recover vigenere key chars: v at positions 3j..3j+2 mod 5
key=[None]*5
for j in range(5):
    for i in range(3): key[(3*j+i)%5]=chr(65+vig[j][i])
print("Vigenere key recovered:","".join(key),"true",A.VIGENERE_KEY)
# check on a fresh message
new=sample_data.corpus_normal()[5000:5600]
c=sc.cipher_body(new)
y=idx(transposition.decrypt(c,perm))
dec="".join(chr(65+((mv(Kinv,[(y[3*t+i]-b[t%5][i])%M for i in range(3)]))[k])) for t in range(len(y)//3) for k in range(3))
print("fresh message decrypted correctly:", dec[:len(new)]==new)

# min known plaintext for V+H (no transposition)
sc4=A.SCENARIOS[3]
for L in (30,45,60,75,90,120,150):
    p=pt[:L]; y=idx(sc4.cipher_body(p)[:L])
    print("V+H KPA with",L,"known chars:", "OK" if affine_attack(idx(p),y,5) else "fail")
