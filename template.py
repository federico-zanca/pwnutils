from pwn import *

binary_name = "{binary}"
e  = ELF(binary_name, checksec=True)
libc = ELF("{libc}", checksec=False)
context.binary = e
#context.terminal = ["konsole", "-e", "sh", "-c"]
context.terminal = ["ghostty", "-e", "sh", "-c"]
context.arch = "amd64"

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]
#onegadgets = one_gadget(libc.path, libc.address)

# shortcuts 
ru  = lambda *x, **y: r.recvuntil(*x, **y)
rl  = lambda *x, **y: r.recvline(*x, **y)
rc  = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa  = lambda *x, **y: r.sendafter(*x, **y)
sl  = lambda *x, **y: r.sendline(*x, **y)
sn  = lambda *x, **y: r.send(*x, **y)
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

def demangle(mangled, offset = 0x0000):
	mid = mangled ^ ((mangled >> 12) + offset)
	return mid ^ (mid >> 24)

def protect_ptr(pos, ptr):
	return (pos >> 12) ^ ptr




if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug(f"{debug_dir}/{{binary_name}}", """
		c
	""", aslr=False)
else:
	r = process(f"{debug_dir}/{{binary_name}}")

{interactions}


r.interactive()
