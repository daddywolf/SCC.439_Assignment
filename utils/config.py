import os

WELCOME = """ ██████╗ ███╗   ██╗██╗     ██╗███╗   ██╗███████╗         ██████╗██╗  ██╗ █████╗ ████████╗
██╔═══██╗████╗  ██║██║     ██║████╗  ██║██╔════╝        ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
██║   ██║██╔██╗ ██║██║     ██║██╔██╗ ██║█████╗          ██║     ███████║███████║   ██║   
██║   ██║██║╚██╗██║██║     ██║██║╚██╗██║██╔══╝          ██║     ██╔══██║██╔══██║   ██║   
╚██████╔╝██║ ╚████║███████╗██║██║ ╚████║███████╗        ╚██████╗██║  ██║██║  ██║   ██║   
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝         ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                                                                                            
By Zhipeng Jiang @Lancaster University     V1.0
"""

PATH = f"{os.getcwd()}/files/"
LOG_FILE = 'secure_log.log'

PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvgaixepsHZAQ0ERiJQow
i1Rt/VIOLGtb3mPUdvSTixirTI5NE+P/8QLpa2oGISk1cZTKb1fp50GtAYX4CiZa
G9KSPTCWE4BCvPMG5bCrNrCtjMsRpx//wzD7fJr+0uzlwz3lx7KK1ZkrJhI0QBeq
b5Q4NS5QnA7yQssp9Va1IL3txXWz/I3s0V2dlLGRfJ9PglpBCutbIUvUmz/d9Vfq
XKhh6fMKR0UjjBfstT2kSvPYPnHyx3948BvukyeBc2DFZam3sEKPtqZoiLMb4LSy
PixWcafYCziSdBc+ExS1AF2Z6Y5bqd7XEXtNVTCR9z7YThEF4FUg8d8j5TBsI/Mk
4QIDAQAB
-----END PUBLIC KEY-----
'''
PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvgaixepsHZAQ0ERiJQowi1Rt/VIOLGtb3mPUdvSTixirTI5N
E+P/8QLpa2oGISk1cZTKb1fp50GtAYX4CiZaG9KSPTCWE4BCvPMG5bCrNrCtjMsR
px//wzD7fJr+0uzlwz3lx7KK1ZkrJhI0QBeqb5Q4NS5QnA7yQssp9Va1IL3txXWz
/I3s0V2dlLGRfJ9PglpBCutbIUvUmz/d9VfqXKhh6fMKR0UjjBfstT2kSvPYPnHy
x3948BvukyeBc2DFZam3sEKPtqZoiLMb4LSyPixWcafYCziSdBc+ExS1AF2Z6Y5b
qd7XEXtNVTCR9z7YThEF4FUg8d8j5TBsI/Mk4QIDAQABAoIBAD0/IEmQFAa3P2QR
Flz/2sOdk9HZF65jb/nOzVUF4WQssFF9cARgMUb5/EfdpVoc0RfpsBGREVezCFL8
XgTPda2QAghs14Izjc8euXNgrN50tYsyjF8EZkgASp5PyqArMKbsFVp3Bl5v/sNH
jMW3mvxZloA1jE+wVY8Hsl9b8gc6AQlPUMChNOvr06RjtoygrdLFmEGmr6JWvL6V
e75gBfDZcNAWHAjK4AYh2xdbqPB28R3x7Y8qk1pmsinlqmBhPDu3UCwAlj73w5nY
C8bLA/hoIXr7W3jo2DsG8jBOTj9n4z66q+hlbJJj4cTNFaU6mGaCSXQxYL0R7agp
HZka7b0CgYEAxPjgGCH7/2BVe8qWrMnFUB6rnbmbSGEZoz9D0UllmRinfqHBLslE
E2rBCqLTxSzy8VK6cm05+NIF4KNWK210XbiINZaATP7i9xBFv3suNU8IJSoaNIAs
/rokKI/cQzMVY7WIpcPOJkMHqmQs1cBLSMaQFnQYwM18tVA+55ZsyAsCgYEA9vjd
YTI04Sab6QTnjlGjawd78Rj4UAO1kSwPtA5AJR2qNpv3MpWEXifJ1XDaBY8IBXBj
aQV+d8eTnh18bG54jB7Ey6NLMht+nzO2xfWUg11Oaw0/lXUCFfbGbucjwxEKXsWU
EgrYBTJb+jGKYJmBEoP38vfOUb0eTKufKzSMnkMCgYBP892yrgjGDmpkh0VF+djX
vrtWmIKJjLCFbSawCyTsUe+bHTl3LkctwoV9Nb7UKHysrDH2RJPlhgrQtjxCAHnd
mQvhBKgrmMK0GqzVHsEQ7nWV8FMWwHiDJTeMJ2j29gNWp9dBwgspyMeRyHvSf+2P
KtpN4u4xRLe8OUhvZMXfJQKBgGW4sO3kkPUfQt4iAAGVTHq71WfDQhsqu/D0Ne+S
YwcmhcICUTmLbb6eIrp/xby+Ya5j0P4jnihVkk5wlJvQkGQeFC5PrpwPyQJneWNl
t+q3VqIvDb5QODC1uJtbJlakwSGxvUAFKV5SlKGjH/yTnR70Lf7r5BW0kDNCCMfx
1+0jAoGBAJlPSWU0/4Z3XdwU2O8N5NHULxgCJ976nvFtkxaepcSFY1aWOgckqNjT
IObT+sBAu4TiMhLtC7nSvlv7tSnvaJhOR6wvSqCaDY2DNoejRlJwZnC4GTFaXD3b
gMFIqMw7jMb3Cwem+bFxmX8SC5q4afNJO0i3jhAtemDUZeRdITyw
-----END RSA PRIVATE KEY-----
'''
