import re

def extract_tokens(template: bytes, actual: bytes):
    def replace(match):
        token = match.group(1)
        if token in (b"*", b"ignore"):
            return b"(?:.+?)"  # non-capturing group for ignore tokens
        else:
            return b"(?P<" + token + b">.+?)"
          
    # Escape curly braces in the template
    pattern = re.escape(template)

    # Replace escaped {token} with named regex groups
    pattern = re.sub(rb'\\\{(\w+)\\\}', replace, pattern)

    regex = re.compile(pattern)
    match = regex.match(actual)
    if match:
        return match.groupdict()
    else:
        return None