import sys

import os

sys.path.append("/pkg/bin")

from ztp_helper import ZtpHelpers

if sys.argv[1] == 'pre':
    print "\n###### Executing a cleanup command ######\n"
    ZtpHelpers(syslog_file='/home/test/syslog.log').xrcmd({'exec_cmd': 'clear logging', 'prompt_response': 'y'})

    ZtpHelpers(syslog_file='/home/test/syslog.log').xrapply_string(cmd="debug icmp")
    # ZtpHelpers().xrcmd({'exec_cmd': 'clear logging'})
if sys.argv[1] == 'after':
    print "\n###### Executing an output command ######\n"
    output = ZtpHelpers(syslog_file='/home/test/syslog.log').xrcmd({"exec_cmd":  "show logging"})

    # print os.popen('source /pkg/bin/ztp_helper.sh && xrcmd "show logging" | grep 255.255.255.254').read()

    # from subprocess import Popen, PIPE
    #
    # process = Popen(['source', '/home/cisco/scripts/ztp_helper.sh', '&&', 'xrcmd',  '"show logging"', '|', 'grep', '255.255.255.254'], stdout=PIPE, stderr=PIPE)
    # stdout, stderr = process.communicate()
    # print stdout
    print output
