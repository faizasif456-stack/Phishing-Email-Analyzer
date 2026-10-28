import re

URL_PARTS = re.compile(r"(?i)^(https?)://([^/?#]*)(.*)$")


def defang(value):
    match = URL_PARTS.match(value)
    if match:
        scheme = match.group(1).lower().replace("http", "hxxp")
        return f"{scheme}://{match.group(2).replace('.', '[.]')}{match.group(3)}"
    return value.replace(".", "[.]").replace("@", "[@]")


def refang(value):
    value = re.sub(r"(?i)^hxxp", "http", value)
    return value.replace("[.]", ".").replace("[@]", "@")
