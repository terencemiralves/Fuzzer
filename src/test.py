import re

def extract_tokens_bytes(template: bytes, actual: bytes):
    """
    Extrait les groupes nommés (ex: {address}) d'une chaîne binaire basée sur un template binaire.
    Le template peut contenir des tokens comme b'{address}'.
    """
    # Regex : échappe les caractères spéciaux sauf les tokens
    # On cherche : b'\{address\}' → on remplace par regex binaire
    pattern = re.escape(template)

    # Remplace tous les \{token\} par des groupes nommés
    pattern = re.sub(rb'\\\{(\w+)\\\}', lambda m: b'(?P<' + m.group(1) + b'>.+?)', pattern)

    # Compile et match
    regex = re.compile(pattern)
    match = regex.match(actual)
    if match:
        return match.groupdict()
    else:
        return None

template = b"check at {address}\nargv[1] = [%1$p]\nfmt=[0x80485f1]\ncheck=0x4030201\n"
actual   = b"check at 0xffa6f1a8\nargv[1] = [%1$p]\nfmt=[0x80485f1]\ncheck=0x4030201\n"

result = extract_tokens_bytes(template, actual)
print(result)
