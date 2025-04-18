import re

a = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)?', '22/tcp open ssh   fdsjljfdsljfkldas')

print(a.group(1))  # 22
print(a.group(2))  # tcp
print(a.group(3))  # ssh