import base64

original_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

print(base64.b64encode(base64.b16decode(original_string.upper())))
