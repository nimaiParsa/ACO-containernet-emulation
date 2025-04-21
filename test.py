import shlex

cmd =  "Hello, World"

cmd = shlex.quote(cmd)

cmd = f"python3 -c {cmd}"



print(cmd)