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

# THE LOG_KEY AND LOG_PASSWORD SHOULD BE STORED CAREFULLY! (I included this as a vulnerability to the vulnerability text documentation.)
LOG_KEY = b'O\xb9\xa8q\xa1\x97\xb9\x00\xc4\x81\x88\x1f6\xf2Q\xf1\xfa\xc8\x9f\x12\xc13{ X\x8a3\x93\x0e\xfd\x17\x1b'
LOG_PASSWORD = b'I WANT HIGHER SCORE!'
