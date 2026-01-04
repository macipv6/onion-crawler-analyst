import re, hashlib

def normalize_text(t:str)->str:
    t = re.sub(r"\s+", " ", t or "").strip()
    return t

def block_hashes(text:str, block_size:int=800)->list[str]:
    t = normalize_text(text)
    blocks = [t[i:i+block_size] for i in range(0, len(t), block_size)]
    return [hashlib.sha256(b.encode("utf-8","ignore")).hexdigest() for b in blocks if b]
