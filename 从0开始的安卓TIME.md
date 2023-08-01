---
title: 从0开始的安卓TIME
date: 2022-09-07 19:45:27
tags:
---
今天终于拿到了我的pixel，万物皆可公费，乐）毕业带不走就入手个Pixel4）

自从给模拟器折磨后我就很久没碰安卓题，碰到即逃避，然而大赛的趋向都是安卓题，从0开始的安卓TIME

感觉换了个新手机一样，呜呼，我的三星与大白兔面基那天不小心摔到，然后无线模块全部坏了，不扯废话了，开始记录！--2022.9.7

# IDA调试类

```
adb shell # 连接shell
su # 变井号提权
./data/local/tmp/android_server # 开启IDA远程调试文件

adb push android_server /data/local/tmp/  # 丢入文件
adb shell chmod 755 /data/local/tmp/android_server # 设置权限
adb forward tcp:23946 tcp:23946 # 转发端口，日后最后换个端口有些反调试会检测
```



```
adb install easy.apk # 先安装该应用
adb install -t *.apk # 有时候需要强制安装

adb shell am start -D -n com.a.easyapk/com.a.easyapk.MainActivity # 利用apktools以调试启动该文件
```

在so里下断直接attach上即可



## NewStarCTF-WEEK2-ur_so_naive

**0x00 Daily Shell Check**

​	无壳

![image-20220928145933061](从0开始的安卓TIME/image-20220928145933061.png)



**0x01 Native调试**

拉进jadx找到主函数可以发现只有个密文，我们的输入会作为passwd，进行 R.id.btn_check 的校验，而该函数是在我们的 native 层，于是解压apk，找到 ur_so_naive\lib\arm64-v8a 下的文件，验证函数都在里面了

找到 Java_com_new_1star_1ctf_u_1naive_MainActivity_encry 函数，很明显在实现一个加密逻辑，部分值我们没有，所以可以通过调试 so 文件获取

首先运行 ida 的远程调试文件

```
./data/local/tmp/android_server64
```

另起个 cmd 转发端口让手机上开启的端口IDA能找到

```
adb forward tcp:23946 tcp:23946
```

选择该选项设置本机调试

![image-20220928151018471](从0开始的安卓TIME/image-20220928151018471.png)

再以调试模式开启该 apk

```
adb shell am start -D -n com.new_star_ctf.u_naive/com.new_star_ctf.u_naive.MainActivity
```

此时手机自动开启了该程序（~~手机自己动了我不玩了~~

再去 IDA attach上该so文件

![image-20220928151307578](从0开始的安卓TIME/image-20220928151307578.png)

随后程序就跑起来了（记得先在so文件里下断点，这样在验证密码的时候就会断在此处）

按几下F9让程序跑起来，此时手机上可以输入，随意输入点就成功断住！



**0x02 GetFlag**

随后就是分析算法逆算法

```C
__int64 __fastcall Java_com_new_1star_1ctf_u_1naive_MainActivity_encry(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        unsigned int len,
        __int64 a5)
{
  __int64 input; // x21
  unsigned __int8 *key; // x23
  __int64 v10; // x22
  __int64 idx; // x8
  unsigned int t; // w11
  __int64 idxxx; // x13
  unsigned int t1; // w11
  char t2; // w12
  char t3; // w12
  char t4; // w12
  bool v18; // zf

  input = (*(*a1 + 1352LL))(a1, a3, 0LL);
  key = (*(*a1 + 1352LL))(a1, a5, 0LL);
  v10 = (*(*a1 + 1408LL))(a1, len);
  if ( len )
  {
    idx = 0LL;
    do
    {
      t = *(input + idx);
      if ( len - 1LL == idx )
        idxxx = 0LL;
      else
        idxxx = idx + 1;
      *(input + idx) = (*(input + idx) >> 1) & 0x7F | (*(input + idx) << 7);// ROR1

      t1 = ((t >> 1) & 0xFFFF807F | (t << 7)) ^ *key;// ROR1 ^ key
      t2 = (t1 << 6) | (t1 >> 2);

      *(input + idx) = t2;

      t3 = (32 * (t2 ^ key[1])) | ((t2 ^ key[1]) >> 3);

      *(input + idx) = t3;

      t4 = (16 * (t3 ^ key[2])) | ((t3 ^ key[2]) >> 4);

      *(input + idx) = t4;

      LOBYTE(t1) = t4 ^ key[3];

      *(input + idx) = t1;
      v18 = len == idx + 1;
      *(input + idx++) = t1 ^ *(input + idxxx);
    }
    while ( !v18 );
  }
  (*(*a1 + 1664LL))(a1, v10, 0LL, len, input);
  return v10;
}
```

一堆ROR加异或的操作，直接反着来即可

```python
enc = [-36, 83, 22, -117, -103, -14, 8, 19, -47, 47, -110, 71, 2, -21, -52, -36, 24, -121, 87, -114, -121, 27, -113, -86]
key = b'FALL'
# enc = [0x57, 0x96, 0xD1, 0x11, 0x52, 0x93, 0xB3]
input = [0x31, 0x32]

enc = [t & 0xFF for t in enc]

def ROR(n, offset, idx):
    if idx == -1:
        return ((n >> offset) & 0x7F | (n << (8 - offset))) & 0xFF
    else:
        return (((n ^ key[idx]) >> offset) | ((n ^ key[idx]) << (8 - offset))) & 0xFF
# i = 0
# t = input[i]
# t1 = ROR(t, 1, -1) ^ key[0]
# print(hex(t1))
# t2 = ROR(t1, 2, -1)
# t3 = ROR(t2, 3, 1)
# t4 = ROR(t3, 4, 2)
# t1 = t4 ^ key[3]
# input[i] = t1 ^ input[i + 1]

for i in range(len(enc) - 1, -1, -1):
    if i == len(enc) - 1:
        ii = 0
    else:
        ii = i + 1
    t1 = enc[i] ^ enc[ii]
    t4 = t1 ^ key[3]
    t3 = ROR(t4, 4, -1) ^ key[2]
    t2 = ROR(t3, 5, -1) ^ key[1]
    t1 = ROR(t2, 6, -1)
    t = ROR(t1 ^ key[0], 7, -1) 
    enc[i] = t
print(bytes(enc))
```

GetFlag!

![image-20220928151745611](从0开始的安卓TIME/image-20220928151745611.png)



Frida RPC 远程调用

那么在看雪上发现一篇文章讲了用RPC直接爆破出来了，那么是什么个原理？

就是我们如果想调用 so 文件里的函数，可以通过 rpc 来实现远程调用，然后直接爆破即可

js部分如下，就是直接从主类中找到了对象随后调用该加密函数也就是encry

然后有个出口 rpc.exports 供给随后直接调用该函数（我是这样理解的，不过不知道是不是每次调用函数都去找了遍对象）

```js
var result;
var resutlt;

function ency(a, b, c){
    Java.perform(function(){
        var mainClass = Java.use("com.new_star_ctf.u_naive.MainActivity");

        Java.choose("com.new_star_ctf.u_naive.MainActivity",{
            onMatch:function(obj){
                result = obj.encry(a, b, c);
                resutlt = bytes2hexstr_2(result);
                send(result);
            },
            onComplete:function(obj){
            }
        })

    });
    return resutlt.toString();
};

function bytes2hexstr_2(arrBytes){
    var str_hex = JSON.stringify(arrBytes);
    return str_hex;
}
rpc.exports = {
    rpcfunc: ency
}
```

python代码如下，原作者代码截一半...弄得我找了好几篇文章才知道哪少了

```python
def frida_rpc(session):
    rpc_hook_js = """
        var result;
        var resutlt;

        function ency(a, b, c){
            Java.perform(function(){
                var mainClass = Java.use("com.new_star_ctf.u_naive.MainActivity");

                Java.choose("com.new_star_ctf.u_naive.MainActivity",{
                    onMatch:function(obj){
                        result = obj.encry(a, b, c);
                        resutlt = bytes2hexstr_2(result);
                        send(result);
                    },
                    onComplete:function(obj){
                    }
                })

            });
            return resutlt.toString();
        };

        function bytes2hexstr_2(arrBytes){
            var str_hex = JSON.stringify(arrBytes);
            return str_hex;
        }
        rpc.exports = {
            rpcfunc: ency
        }
        """
    # 添加 js 脚本
    script = session.create_script(rpc_hook_js)
#    消息监听，不过这里用不上
#    script.on('message', message_header)

    # 加载会话
    script.load()
    return script


# 连接安卓机上的frida-server
device = frida.get_usb_device()
session = device.attach(25485)
script = frida_rpc(session)


enc = [-36, 83, 22, -117, -103, -14, 8, 19, -47, 47, -110, 71, 2, -21, -52, -36, 24, -121, 87, -114, -121, 27, -113, -86]
flag = "flag{"
k = 5

for j in range(0, 16):
    for i in string.printable:
        test = flag + i
        ret = script.exports.rpcfunc(test, len(test), "FALL")
        json_obj = json.loads(ret)
        if json_obj[k - 1] == enc[k - 1]:
            k += 1
            flag = flag + i
            print(flag)
```

爆破flag的感觉真不错

![image-20221027174158003](从0开始的安卓TIME/image-20221027174158003.png)





## NewStarCTF-WEEK3-哈德兔的口

今日做一题发现，这个Native调试方法并不通用，还要一个JDB附加的操作？？之前都不用，发现搜寻文章并没有得到我想要的答案

那么 哈德兔的口 这题，就是等ida attach上去后需要jdb附加才能继续运行

```
jdb -connect com.sun.jdi.SocketAttach:port=8600,hostname=localhost
```

该端口号看ddms，jdb就用的java的jdk里的lib

随后要记得设置这个三个，让so文件加载的时候停止，这样是为了找到我们想要的libcheck

![image-20221021205543320](从0开始的安卓TIME/image-20221021205543320.png)

等看ida的底下的信息出现了该so文件，ida出了个弹窗，也就是两个模块名字重复，好像是apk加载时候又有个先相同的，这样选择same ida就会卡起来，随后就未响应了，估计是什么冲突了，所以选了not same

```
Debugger found two modules with same base name but different paths
This could happen if the program loads the module from a path different than the specified input file


Is the loaded file
'/data/app/com.newstarctf.decode-IlS4t4KPe_ksTzUFrzjD8Q==/lib/arm64/libcheck.so'
the same as the input file
'C:\Users\Pz\Desktop\NEW\哈德兔的口\lib\arm64-v8a\libcheck.so'?
```

而这新加载进来的so和我们当初下的在主函数下的断点已经不一样了，所以要重新定位到主函数下断点，那么学到个新办法就是在Modules里搜该so，然后点开再去里面搜函数即可！

![image-20221021210114143](从0开始的安卓TIME/image-20221021210114143.png)

随后再下个断点F9直接跑过去即可，这时候可以把suspend on process....三个按钮去掉，不用再管新载入的库等

还有这题获取加载字符串的事，就是直接hook decode函数打印即可

```js
function test(){
    Java.perform(function(){
        var mainClass = Java.use("com.newstarctf.decode.MainActivity");

        mainClass.decode.implementation = function(a){
            var result = this.decode(a)
            console.log(result)
            return a

        }

    })
};

test();
```



## 祥云杯-GetTheCorrectKey

这题Frida上不去so层直接找函数也调不了，现在知道调试so文件最开始是JNI_onLoad

还是按上个方法调到关键搜然后搜索JNI_onLoad开始调试，发现基本全是检测调试或者Frida的

只有这里才是真正的

![image-20221102165054931](从0开始的安卓TIME/image-20221102165054931.png)

由于不需要什么参数我调试过完检测Frida的之后就直接 Ctrl + N 过去了，随后就没有什么反调试了，一路跟着调试会发现有个SMC动态解密一段代码

如果按别人手写解密那么就是这样（有点好奇如何去掉 initArray加密）

我是动调过去的比较难看也可能是 Ctrl + N 的原因导致

![image-20221102165250434](从0开始的安卓TIME/image-20221102165250434.png)

动调可以直接提取出解密完的dex文件，这里解的就是 assets 下的 whoami 就成功解密成一个 dex 了

然后利用反射技术再 native层 调用 java层的函数，所以真正运行是这个文件

拉进 jadx 一眼丁真是 RC6 加 BASE58 解密即可

```
https://www.lddgo.net/encrypt/rc6
```

![image-20221102165636621](从0开始的安卓TIME/image-20221102165636621.png)

# Frida类

注意放到手机上的frida_server要和python版本的frida库一致

```
adb shell
su
./data/local/tmp/frida-server
```

## NewStarCTF-WEEK1-艾克体悟题

**0x00 Daily Shell Check**

无壳

![image-20220928143138914](从0开始的安卓TIME/image-20220928143138914.png)



**0x01 Frida hook**

这题jadx的话会把一些编译优化，所以我用JEB，看主程序可知只要点10000下，让FlagActivity.this.cnt变为10000即可

```java
package com.droidlearn.activity_travel;

import android.os.Bundle;
import android.view.View$OnClickListener;
import android.view.View;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

public class FlagActivity extends AppCompatActivity {
    private int cnt;

    public FlagActivity() {
        super();
        this.cnt = 0;
    }

    static int access$000(FlagActivity arg0) {
        return arg0.cnt;
    }

    static int access$004(FlagActivity arg1) {
        int v0 = arg1.cnt + 1;
        arg1.cnt = v0;
        return v0;
    }

    protected void onCreate(Bundle arg4) {
        super.onCreate(arg4);
        this.setContentView(0x7F0B002D);
        this.findViewById(0x7F080058).setOnClickListener(new View$OnClickListener(this.findViewById(0x7F080181), this.findViewById(0x7F080097)) {
            public void onClick(View arg3) {
                this.val$tv_cnt.setText(Integer.toString(FlagActivity.access$004(FlagActivity.this)));
                if(FlagActivity.this.cnt >= 10000) {
                    Toast.makeText(FlagActivity.this, this.val$str.getText().toString(), 0).show();
                }
            }
        });
    }
}


```



**0x02 GetFlag**

~~那么一个思路就是点一万下~~

另一个思路就是hook access$000 函数让该函数直接返回10000，判断就成立了，我们就GetFlag了

所以此时就可以用 Frida 了，就是在程序运行的时候 hook 返回值变为1000即可

```
./data/local/tmp/frida-server # 进入shell Frida启动！
```

再进入一个shell 启动指定控件

```
am start -n com.droidlearn.activity_travel/com.droidlearn.activity_travel.FlagActivity
```

查看我们启动控件的PID

```
C:\Users\Pz>frida-ps -aU
  PID  Name             Identifier
-----  ---------------  ---------------------------------------
10738  Activity_Travel  com.droidlearn.activity_travel
 9870  Android Auto     com.google.android.projection.gearhead
23407  Google           com.google.android.googlequicksearchbox
 9063  Google Play 商店   com.android.vending
 9022  Google Play 电影   com.google.android.videos
11206  Magisk           com.topjohnwu.magisk
```

接着我们就是 attach 上了

```python
import frida

# 连接安卓机上的frida-server
device = frida.get_usb_device()
session = device.attach(10738)
```

接着可以编写我们的 js 脚本用来重写要hook的类方法

```js
console.log("Script loaded successfully ");
Java.perform(function x() {
    console.log("Inside java perform function");
    //定位类
    var my_class = Java.use("com.droidlearn.activity_travel.FlagActivity");
    console.log("Java.Use.Successfully!");
    //在这里更改类的方法的实现（implementation）
    my_class.access$000.implementation = function(x){
        //打印替换前的参数
        console.log("Successfully!");
        return 10001;
    }
});
```

接着让我们的 js 脚本加载到该目标进程上即可

```python
import frida

# 连接安卓机上的frida-server
device = frida.get_usb_device()
session = device.attach(10738)

# 加载hooook.js脚本
with open("hooook.js", encoding='UTF-8') as f:
    script = session.create_script(f.read())
script.load()

# 脚本会持续运行等待输入
input()
```

运行脚本，再点击 CLICK ME 即可！

GetFlag!



## [网鼎杯 2020 青龙组]bang

历史遗留题，当初dexdump的报错一直不知道该怎么修，今日Frida学习过程中突然感觉又行了，于是真行了。--2023.7.31

**0x00 Daily Shell Check**

第一代壳，可以直接 dump 脱

![image-20230731102443034](从0开始的安卓TIME/image-20230731102443034.png)

随后我就在不断尝试 frida-dexdump 脱壳

> https://github.com/hluwa/FRIDA-DEXDump 

以一种 attach 的方式脱

```
frida-dexdump.exe -U -p 19757
```

但是不行，各种各样的报错，于是换了一个脱法

```
frida-dexdump.exe -U -f com.example.how_debug -o .
```

这样 spwan 挂起的方式就能成功 dump 了，估计是之前 attach 时机的问题，成功 dump 下来就能分析了，不过还发现一个把所有 dump 下来的 dex 打包的脚本

```python
import os
import zipfile
import argparse

def rename_class(path):
    files = os.listdir(path)
    dex_index = 0
    if path.endswith('/'):
        path = path[:-1]
        print(path)
    for i in range(len(files)):
        if files[i].endswith('.dex'):
            old_name = path + '/' + files[i]
            if dex_index == 0:
                new_name = path + '/' + 'classes.dex'
            else:
                new_name = path + '/' + 'classes%d.dex' % dex_index
            dex_index += 1
            if os.path.exists(new_name):
                continue
            os.rename(old_name, new_name)
    print('[*] 重命名完毕')

def extract_META_INF_from_apk(apk_path, target_path):
    r = zipfile.is_zipfile(apk_path)
    if r:
        fz = zipfile.ZipFile(apk_path, 'r')
        for file in fz.namelist():
            if file.startswith('META-INF'):
                fz.extract(file, target_path)
    else:
        print('[-] %s 不是一个APK文件' % apk_path)

def zip_dir(dirname, zipfilename):
    filelist = []
    if os.path.isfile(dirname):
        if dirname.endswith('.dex'):
            filelist.append(dirname)
    else:
        for root, dirs, files in os.walk(dirname):
            for dir in dirs:
                # if dir == 'META-INF':
                # print('dir:', os.path.join(root, dir))
                filelist.append(os.path.join(root, dir))
            for name in files:
                # print('file:', os.path.join(root, name))

                filelist.append(os.path.join(root, name))

    z = zipfile.ZipFile(zipfilename, 'w', zipfile.ZIP_DEFLATED)
    for tar in filelist:
        arcname = tar[len(dirname):]

        if ('META-INF' in arcname or arcname.endswith('.dex')) and '.DS_Store' not in arcname:
            # print(tar + " -->rar: " + arcname)
            z.write(tar, arcname)
    print('[*] APK打包成功，你可以拖入APK进行分析啦！')
    z.close()

if __name__ == '__main__':
    args = {
        'dex_path': 'C:\\Users\\PZ\\Desktop\\dex',
        'apk_path': 'C:\\Users\\PZ\\Desktop\\signed.apk',
        'output': 'Z:\\rev\\rev.apk'
    }

    rename_class(args['dex_path'])
    extract_META_INF_from_apk(args['apk_path'], args['dex_path'])
    zip_dir(args['dex_path'], args['output'])

```

不过好像是有点报错，不过雀氏合并了，java层 flag 就明文就不写辣

# 记录报错	

crosshatch:/ # ./data/local/tmp/frida-server

```

{"type":"error","description":"Error: invalid address","stack":"Error: invalid address\n    at Object.value [as patchCode] (frida/runtime/core.js:200:1)\n    at qt (frida/node_modules/frida-java-bridge/lib/android.js:994:1)\n    at Bt.activate (frida/node_modules/frida-java-bridge/lib/android.js:1047:1)\n    at Ht.replace (frida/node_modules/frida-java-bridge/lib/android.js:1094:1)\n    at Function.set [as implementation] (frida/node_modules/frida-java-bridge/lib/class-factory.js:1010:1)\n    at Function.set [as implementation] (frida/node_modules/frida-java-bridge/lib/class-factory.js:925:1)\n    at installLaunchTimeoutRemovalInstrumentation (/internal-agent.js:424:24)\n    at init (/internal-agent.js:51:3)\n    at c.perform (frida/node_modules/frida-java-bridge/lib/vm.js:11:1)\n    at y._performPendingVmOps (frida/node_modules/frida-java-bridge/index.js:238:1)","fileName":"frida/runtime/core.js","lineNumber":200,"columnNumber":1}
```

改为permissive 0

```
Ccrosshatch:/ # getenforce
Enforcing
crosshatch:/ # setenforce 0
crosshatch:/ # getenforce
Permissive
crosshatch:/ # ./data/local/tmp/frida-server
```





