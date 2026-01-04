from langdetect import detect, DetectorFactory
DetectorFactory.seed = 0

def detect_lang(text:str)->str|None:
    t = (text or "").strip()
    if not t: return None
    try:
        return detect(t)
    except Exception:
        return None
