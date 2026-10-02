# SPDX-License-Identifier: AGPL-3.0-only
# stdio adapter used only by a one-off host CLI MCP configuration. Generated
# disposable SSH key stays on the host; the model never receives it as content.
import os, subprocess, sys, threading
try:
 name=sys.argv[1]
 if len(sys.argv)!=2 or name not in ['claude','codex']:raise ValueError()
 port=os.environ['BLINDPASS_P05_HELPER_SSH_PORT']
 if not port.isdigit() or not 1024<=int(port)<=65535:raise ValueError()
 key=os.environ['BLINDPASS_FLEET_SSH_KEY']
 child=subprocess.Popen(['ssh','-i',key,'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=3','-p',port,
  'blindpass@127.0.0.1','sudo','/usr/lib/blindpass/login/runtime/bin/node','/tmp/browser-handoff/ai-client-connect-guest.mjs',name,'model'],stderr=subprocess.PIPE)
 def discard():
  while child.stderr.read(8192):pass
 thread=threading.Thread(target=discard,daemon=True);thread.start()
 sys.exit(child.wait())
except (ValueError,KeyError,OSError):sys.exit(70)
