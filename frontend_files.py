import os

for root, dirs, files in os.walk('c:/Users/joseph/Documents/supply-chain-security/frontend'):
    if 'node_modules' in dirs:
        dirs.remove('node_modules')
    if '.git' in dirs:
        dirs.remove('.git')
    for file in files:
        print(os.path.relpath(os.path.join(root, file), 'c:/Users/joseph/Documents/supply-chain-security/frontend'))
