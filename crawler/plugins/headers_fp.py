def headers_fingerprint(headers:dict)->str:
    # stabile, einfache Fingerprint-Strategie: sortierte "Name:Value"-Liste hashen
    import hashlib
    canon = "\n".join([f"{k.lower().strip()}:{' '.join(v.split()) if isinstance(v,str) else v}" 
                       for k,v in sorted(headers.items(), key=lambda x: x[0].lower())])
    return hashlib.sha256(canon.encode("utf-8","ignore")).hexdigest()
