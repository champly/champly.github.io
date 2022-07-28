---
title: Kubernetes cni 网络插件调试
date: 2019-07-29 14:46:00
categories: CloudNative
tags:
  - Kubernetes
  - CNI
---

最近搭建 `Kubernetes` 集群的时候使用的网络插件是 `bridge` + `host-local`

## 关于cni插件

安装 `kubelet` 的时候会有一个 `kubernetes-cni-version-0.x86_64.rpm` 的依赖文件，安装了之后会在 `/opt/cni/bin` 下面会有各种网络插件

``` sh
# rpm -qpl kubernetes-cni-0.7.5-0.x86_64.rpm
warning: kubernetes-cni-0.7.5-0.x86_64.rpm: Header V4 RSA/SHA512 Signature, key ID 3e1ba8d5: NOKEY
/opt/cni
/opt/cni/bin
/opt/cni/bin/bridge
/opt/cni/bin/dhcp
/opt/cni/bin/flannel
/opt/cni/bin/host-device
/opt/cni/bin/host-local
/opt/cni/bin/ipvlan
/opt/cni/bin/loopback
/opt/cni/bin/macvlan
/opt/cni/bin/portmap
/opt/cni/bin/ptp
/opt/cni/bin/sample
/opt/cni/bin/tuning
/opt/cni/bin/vlan
```

所有的 `cni` 插件在 `spec-v0.3.1` 之前只实现两个接口 `add`, `del`。在 `spec-v0.4.0` 之后会在 `del` 之前执行 `check` ,所以多了一个 `check` 接口。

版本差异: [Container Network Interface Specification](https://github.com/containernetworking/cni/blob/master/SPEC.md)

## 配置文件使用的 `cni` 版本

`cni` 插件使用的插件配置地址 `/etc/cni/net.d/` 下面的文件，根据排序取第一个配置文件信息

``` sh
# cat /etc/cni/net.d/cni.conf
{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "bridge",
    "bridge": "cni0",
    "isDefaultGateway": true,
    "forceAddress": false,
    "ipMasq": true,
    "hairpinMode": true,
    "ipam": {
        "type": "host-local",
        "ranges": [
            [
                {
                    "subnet": "10.13.0.0/22",
                    "rangeStart": "10.13.3.8",
                    "rangeEnd": "10.13.3.253",
                    "gateway": "10.13.3.254"
                }
            ]
        ],
        "routes": [
            {
                "dst": "0.0.0.0/0"
            }
        ],
        "dataDir": "/opt/data/cni"
    }
}
```

配置具体信息可以查看 [源码plugins里面的插件README.md](https://github.com/containernetworking/plugins/tree/master/plugins)

比如我们使用的 `host-local`，我需要知道 `cni` 版本怎么查看呢？

### 查看安装的 `kubernetes-cni` 版本

安装的时候知道是 `kubernetes-cni-0.7.5-0.x86_64.rpm`，所以对应的版本信息是 `0.7.5`

### 查看源码 `host-local` 注册的版本信息

选择 `plugin` 插件版本是 `0.7.5`，查看 `host-local` 注册信息 [源码](https://github.com/containernetworking/plugins/blob/v0.7.5/plugins/ipam/host-local/main.go)

``` golang
func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
```

可以看到版本是All

### 查看 `plugin` 使用的 `cni` 版本

同上一步，选择源码文件的提交 `tag` 为 `0.7.5`，查看 `plugins` 使用的 `cni` 版本信息 [源码](https://github.com/containernetworking/plugins/blob/v0.7.5/vendor/github.com/containernetworking/cni/pkg/version/version.go)

``` golang
// Legacy PluginInfo describes a plugin that is backwards compatible with the
// CNI spec version 0.1.0.  In particular, a runtime compiled against the 0.1.0
// library ought to work correctly with a plugin that reports support for
// Legacy versions.
//
// Any future CNI spec versions which meet this definition should be added to
// this list.
var Legacy = PluginSupports("0.1.0", "0.2.0")
var All = PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1")
```

可以看到All对应的版本信息支持 "0.1.0", "0.2.0", "0.3.0", "0.3.1",所以我就可以写 `0.3.1` 了

## 调试 `cni`

在上面我们的 `cni` 版本是 `0.3.1`,所以在查看 [源码](https://github.com/containernetworking/cni) 的时候选择 spec-v0.3.1

在 `README.md` 里面有测试方法

``` sh
$ CNI_PATH=$GOPATH/src/github.com/containernetworking/plugins/bin
$ cd $GOPATH/src/github.com/containernetworking/cni/scripts
$ sudo CNI_PATH=$CNI_PATH ./priv-net-run.sh ifconfig
eth0      Link encap:Ethernet  HWaddr f2:c2:6f:54:b8:2b  
          inet addr:10.22.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
          inet6 addr: fe80::f0c2:6fff:fe54:b82b/64 Scope:Link
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:1 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:1 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:90 (90.0 B)  TX bytes:0 (0.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

其中我们只需要使用到 `scripts` 下面的 `priv-net-run.sh` 和 `exec-plugins.sh` 这两个文件

把这两个文件下载到本地，然后添加可执行权限

添加 `/etc/cni/net.d/` 下面的 `cni` 配置，添加 `CNI_PATH`

``` sh
[root@10 tmp]# export CNI_PATH=/opt/cni/bin/
[root@10 tmp]# ./priv-net-run.sh
```

其中 `/opt/cni/bin` 就是 `kubernetes-cni-0.7.5-0.x86_64.rpm` 对应的插件目录，如果没有修改就是用这个就可以了

可以修改 `shell` 脚本来调试 `cni` 插件，比如我下面修改之后可以看到执行过程

``` sh
[root@10 tmp]# ./priv-net-run.sh
add 7ac145c133dc63c2 /var/run/netns/7ac145c133dc63c2
netconf:/etc/cni/net.d/cni.conf
name:mynet
plugin:bridge
res:{
    "cniVersion": "0.3.1",
    "interfaces": [
        {
            "name": "cni0",
            "mac": "76:02:71:5b:9c:79"
        },
        {
            "name": "vetheb50e2bb",
            "mac": "76:02:71:5b:9c:79"
        },
        {
            "name": "eth0",
            "mac": "ce:bf:1f:fc:ff:d1",
            "sandbox": "/var/run/netns/7ac145c133dc63c2"
        }
    ],
    "ips": [
        {
            "version": "4",
            "interface": 2,
            "address": "10.13.3.23/22",
            "gateway": "10.13.3.254"
        }
    ],
    "routes": [
        {
            "dst": "0.0.0.0/0"
        },
        {
            "dst": "0.0.0.0/0",
            "gw": "10.13.3.254"
        }
    ],
    "dns": {}
}
No command specified
del 7ac145c133dc63c2 /var/run/netns/7ac145c133dc63c2
netconf:/etc/cni/net.d/cni.conf
name:mynet
plugin:bridge
res:
```

---

参考资料:
- [浅谈k8s cni 插件](https://segmentfault.com/a/1190000017182169)
