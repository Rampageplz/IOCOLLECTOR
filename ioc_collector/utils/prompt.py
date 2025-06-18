from typing import Dict

DEFAULT_OTX_KEY = "a7a130767a8d7f9396430edcf032a1bb8f5c033392e32b95f3d0d543e04880ff"

def prompt_api_keys(existing: Dict[str, str]) -> Dict[str, str]:
    print("Configuracao inicial das chaves de API")
    resp = input("Deseja editar as chaves agora? [s/N] ").strip().lower()
    if resp != "s":
        return {
            "OTX_API_KEY": existing.get("OTX_API_KEY") or DEFAULT_OTX_KEY,
            "URLHAUS_API_KEY": existing.get("URLHAUS_API_KEY", ""),
        }

    update = {}
    otx = input("OTX API Key (Enter para usar padrao): ").strip()
    if not otx:
        otx = DEFAULT_OTX_KEY
    update["OTX_API_KEY"] = otx

    urlhaus = input("URLHaus API Key (opcional, Enter para deixar vazio): ").strip()
    update["URLHAUS_API_KEY"] = urlhaus
    return update
