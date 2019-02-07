import os
import sys
import subprocess
import logging

logger = logging.getLogger("tfuzz.utils")

from fuzzer import Fuzzer as __angr_Fuzzer

def create_dict(binary, dict_filename):
    create_dict_script = os.path.join(__angr_Fuzzer._get_base(),
                                      "bin", "create_dict.py")
    args = [sys.executable, create_dict_script, binary]
    
    with open(dict_filename, 'wb') as df:
        p = subprocess.Popen(args, stdout=df)
        retcode = p.wait()
        df.close()

    return_ok = retcode == 0 and os.path.getsize(dict_filename)
    if return_ok:
        # angr prints 'wtf' on some lines, I think due to this file https://github.com/angr/angr/blob/8b1f0325187f28ba7721ee1e9a1f33f46394c487/angr/analyses/cfg/cfg_fast.py
        # so I remove these lines and log it
        with open(dict_filename, 'rb') as df:
            lines = df.readlines()
            df.close()
            WTF = b'wtf\n'
            if WTF in lines:
                logger.warn("Found 'wtf' lines in dictionary. Removing them") 
            content = b''.join([line for line in lines if line != WTF])
            with open(dict_filename, 'wb') as df:
                df.write(content)

    return return_ok

def replace_input_placeholder(target_opts, input_file,
                              input_placeholder='@@'):
    if target_opts == None:
        return None

    if input_file == None or input_placeholder == None:
        raise ValueError("input_file and input_placeholder could not be None")

    if not isinstance(input_placeholder, str) or \
       not isinstance(input_file, str) :
        raise ValueError("input_file and input_placeholder must be of str type")
    
    return [input_file if e == input_placeholder else e for e in target_opts]
