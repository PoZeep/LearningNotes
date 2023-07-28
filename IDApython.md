---
title: IDApython
date: 2022-09-14 11:56:44
tags:
---
由于之前存放的脚本都太乱了，突然想起我可以开个笔记整理一下）



有网先看文章）

> https://wonderkun.cc/2020/12/11/idapython%E4%BD%BF%E7%94%A8%E7%AC%94%E8%AE%B0/
>
> ...



断点设置

```python
addr = 0x0056457AE08CA6
idc.add_bpt( addr )
```

# Norm

## TakeResource

```python
from ida_bytes import *

addr = 0x00000140003040
len = 0x34166
f = open("ans.exe", "wb")
for i in range(len):
    f.write(bytes([get_byte(addr)]))
    addr += 1
f.close()
print('OK!')
```



## 单字节SMC

```python
st = 0x40107C

for i in range(121):
	ch = get_wide_byte(st + i)						
	patch_byte(st + i, (ch ^ 0xA2) + 34)	
print('OK!')	
```



## 四字节SMC

```python
xorKey = {8723: 2533025110152939745, 8739: 5590097037203163468, 8755: 17414346542877855401, 8771: 17520503086133755340, 8787: 12492599841064285544, 8803: 12384833368350302160, 8819: 11956541642520230699, 8835: 12628929057681570616, 8851: 910654967627959011, 8867: 5684234031469876551, 8883: 6000358478182005051, 8899: 3341586462889168127, 8915: 11094889238442167020, 8931: 17237527861538956365, 8947: 17178915143649401084, 8963: 11176844209899222046, 8979: 18079493192679046363, 8995: 7090159446630928781, 9011: 863094436381699168, 9027: 6906972144372600884, 9043: 16780793948225765908, 9059: 7086655467811962655, 9075: 13977154540038163446, 9091: 7066662532691991888, 9107: 15157921356638311270, 9123: 12585839823593393444, 9139: 1360651393631625694, 9155: 2139328426318955142, 9171: 2478274715212481947, 9187: 12876028885252459748, 9203: 18132176846268847269, 9219: 17242441603067001509, 9235: 8492111998925944081, 9251: 14679986489201789069, 9267: 13188777131396593592, 9283: 5298970373130621883, 9299: 525902164359904478, 9315: 2117701741234018776, 9331: 9158760851580517972}

addr = 0x2213

while True:
    data = get_qword(addr)
    key = xorKey[addr]
    dec = data ^ key
    idc.patch_qword(addr, dec)
    addr += 16
```

# 常见花？

## MRCTF-shit

```python
st = 0x004812F0
end = 0x00481452


def patchNop(start, end):
	for i in range(start, end):
		ida_bytes.patch_byte(i, 0x90)


def nextInstr(addr):
	return addr + idc.get_item_size(addr)


addr = st
while ( addr < end ):
	next = nextInstr(addr)
	addnext = idc.get_operand_value(next, 0)
#	print(hex(anext))
	if idc.print_insn_mnem(next) == "call" and idc.print_insn_mnem(addnext) == "add":
		retnext = nextInstr(addnext)
		addr = nextInstr(retnext)
		patchNop(next, addr)
		print("Patch: %X" %next)
	else:
		addr = next
```

## CCB-Hole

```python
addr = 0x4011E0
end = 0x401A3B
while ( addr < end ):
	if ( get_wide_byte(addr) == 0xEB and get_wide_byte(addr + 1) == 0xFF ):
		patch_byte(addr, 0x90)
	elif ( get_wide_byte(addr) == 0x66 and get_wide_byte(addr + 1) == 0xB8 ):
		nop(addr, addr + 9)
	addr += 1
print('OK!')
```



# 虚假控制流

```python
st = 0x4007E0
end = 0x401154

def patch_nop(start, end):
	for i in range(start, end):
		ida_bytes.patch_byte(i, 0x90)

def next_instr(addr):					            		#get_item_size 获取指令或数据长度，这个函数的作用就是去往下一条指令
	return addr + idc.get_item_size(addr)

addr = st
while (addr < end):
	next = next_instr(addr)
	if "ds:x" in idc.GetDisasm(addr):	        			#idc.GetDisasm(addr)得到addr的反汇编语句
		while (True):
			addr = next
			next = next_instr(addr)
			if "jnz" in idc.GetDisasm(addr):
				dest = idc.get_operand_value(addr, 0)       #得到操作数,即指令后的数 例如 jz 偏移地址 于是get_oprand_value获得偏移地址
				ida_bytes.patch_byte(addr, 0xE9)            #改addr地址的机器码为jmp
				ida_bytes.patch_byte(addr + 5, 0x90)        #addr + 5的位置改成nop
				offset = dest - (addr + 5)                  #调整为正确的偏移地址 也就是相对偏移地址 - 当前指令后的地址
				ida_bytes.patch_dword(addr + 1, offset)     #把偏移地址放到 jmp xxxx nop
				print("patch bcf: 0x%x" % addr)
				addr = next
				patch_nop(next, next + 3)					#把无用的jmp xxx全部nop掉
				break
	else:
		addr = next
```



# 栈混淆

```python
start = 0x807FEC0
end = 0x8080AD1

address = [0 for i in range(5)]
callTarget = ["lea", "lea", "mov", "jmp"]
retnTarget = ["lea", "mov", "and", "lea", "jmp"]


def nop(s, e):
	while (s < e):
		patch_byte(s, 0x90)
		s += 1

def turnCall(s, e, h):
	# nop掉call之前的值
	nop(s, e)
	patch_byte(e, 0xE8)
	# 把后面的花指令去掉 重新计算去花长度
	huaStart = next_head(e)
	huaEnd = h
	nop(huaStart, huaEnd)

def turnRetn(s, e):
	nop(s, e)
	# 注意原来是jmp xxx
	# 所以前面nop掉一个 后面改成retn
	patch_byte(e, 0x90)
	patch_byte(e + 1, 0xC3)

p = start
while p < end:
	address[0] = p
	address[1] = next_head(p)
	address[2] = next_head(address[1])
	address[3] = next_head(address[2])
	address[4] = next_head(address[3])

	for i in range(0, 4):
		if print_insn_mnem(address[i]) != callTarget[i]:
			break
	else:
		turnCall(address[0], address[3], get_operand_value(address[1], 1))
		p = next_head(next_head(address[3]))
		continue

	for i in range(0, 5):
		if print_insn_mnem(address[i]) != retnTarget[i]:
			break
	else:
		turnRetn(address[0], address[4])
		p = next_head(next_head(address[4]))
		continue

	p = next_head(p)
```



# tttree

还没去明白的一个花，SUSCTF2022的该题

```python
import struct
start = 0x140001000
end = 0x14001C694

address_m = [0 for x in range(11)]
address_target = ['push    rax','push    rax','pushfq','call    $+5','pop     rax','add     rax,','mov     ','popfq','pop     rax','retn']

def check1():
    cnt = 0
    for i in range(9):
        if i == 5 or i == 6:
            cnt += GetDisasm(address_m[i]).find(address_target[i]) != -1 # 找不到就是返回-1了
        else:
            cnt += GetDisasm(address_m[i]) == address_target[i]
    return cnt == 9

def check2(x,y):
    cnt = 0
    cnt += print_insn_mnem(x) == "push"
    cnt += print_insn_mnem(y) == "pop"
    cnt += print_operand(x,0) == print_operand(y,0) # print_operand获取操作数    
    return cnt == 3

def check3(): # 如果 push 的是一个立即数
    cnt = 0
    cnt += print_insn_mnem(address_m[0]) == "push"
    cnt += get_operand_type(address_m[0], 0) == o_imm
    return cnt == 2

def nop(u,v):
    patch_add = u
    while(patch_add < v):
        patch_byte(patch_add,0x90) 
        patch_add += 1

p = start
while p <= end:
    address_m[0] = p
    p = next_head(p) # next_head取当前指令的下条指令地址
    while print_insn_mnem(p) == "nop": # print_insn_mnem获取指定地址的助记符
        p = next_head(p)
    if check2(address_m[0],p) == 1: # 这段就是把混淆2去掉
        p = next_head(p)
        nop(address_m[0],p)
    else:
        p = address_m[0]
    address_m[0] = p
    for i in range(1,11):
        address_m[i] = next_head(address_m[i-1]) # 放入数组的下一条地址 也就是混淆1形式的九条指令 加形式之外的一条
    
    if check1() == 1:
        addri = get_operand_value(address_m[5], 1)
        addri += address_m[4] # 算出要跳转的绝对地址
        if address_target[9] == GetDisasm(address_m[9]):
            addri -= (address_m[0] + 5) # 算出相对第一条指令的相对地址
            patch_byte(address_m[0],0xE9)
            patch_dword(address_m[0]+1,addri & 0xffffffff)
            nop(address_m[0]+5,address_m[10])
            p = address_m[10]
        else:
            patch_byte(address_m[0],0x68) # 还有一种形式就是push一个值
            patch_dword(address_m[0]+1,addri & 0xffffffff)
            nop(address_m[0]+5,address_m[9])
            p = address_m[9]
    else:
        p = address_m[1]

p = start
while p <= end:   
    address_m[0] = p
    address_m[1] = next_head(p)
    if check3() == 1:
        print(hex(address_m[0]))
        addri = get_operand_value(address_m[0], 0) + 2 ** 32
        p = address_m[1]
        while print_insn_mnem(p) == "nop":
            p += 1
        if print_insn_mnem(p) == "jmp":
            addrj = struct.unpack('<I', get_bytes(p + 1, 4))[0] + p - address_m[0]
            addri -= p + 5
            if addri < 0:
                addri += 2 ** 32
            patch_byte(address_m[0], 0xe8)
            patch_dword(address_m[0]+1, addrj & 0xffffffff)
            patch_byte(p, 0xe9)
            p += 1
            patch_dword(p, addri)
            p += 4
    else:
        p = address_m[1]
    
print("Finish")
```

