import itertools
import numpy

# user we want concatenate
user = 'support'
 
# Append suffix / prefix to user
arch = open('/home/marcos/htb-academy/broken_authentication/SecLists-master/Fuz>

for linea in arch:
    pre_user = [user + linea.rstrip()]
    print (''.join(pre_user))
    sub_user = [linea.rstrip() + user]
    print (''.join(sub_user))
    dot_user = [user + '.' + linea.rstrip()]
    print (''.join(dot_user))


arch.close()
