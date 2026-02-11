---
title: "Reverse engineering Windows' TCP PartitionTable, bringing back Volatility's good old netscan module"
date: 2026-02-10T00:00:00+00:00
publishdate: 2026-02-10
lastmod: 2026-02-11
draft: false
aliases:
  - /reversing-windows-tcp-partition-table-bringing-back-volatility-netscan-module/
---



We start tracing from `GetTcpTable`, which is just a wrapper over `GetTcpTableInternal`. This function is responsible for processing the TCP table data returned from a call to `NsiAllocateAndGetTable` . 

 `NsiAllocateAndGetTable` carries our analysis to the kernel side, by invoking the handler for `0x12001B`  IOCTL code of the `nsiproxy.sys` 

nsiproxy is a broker between the user mode clients and the kernel mode nsi providers, let's take a look at `nsiproxy!NsippDispatch` to see which provider it will have to trigger in our case.

```c
switch ( LowPart )
  {
    case 0x12001B:
      Parameter = NsippEnumerateObjectsAllParameters(Parameters, Options, RequestorMode, &a2->IoStatus.Information);
      break;
...
```

```c
__int64 nsiproxy!NsippEnumerateObjectsAllParameters(__int128 *Address, SIZE_T Length, char a3, _QWORD *a4)
{
    ... // here it will probe the buffer for write
    NsiEnumerateObjectsAllParametersEx(v14);
    ...
}
```

```c
// netio!NsiEnumerateObjectsAllParametersEx
__int64 NsiEnumerateObjectsAllParametersEx(__int64 req)
{
    for (entry = NsiNmpList; entry != &NsiNmpList; entry = entry->Flink)
    {
        if (entry->ModuleId->Type == 1 && 
            memcmp(&entry->ModuleId->Guid, req->ModuleId->Guid, 16) == 0)
        {
            provider = entry->DispatchTable;
            break;
        }
    }

    tableEntry = &provider->InformationObject[req->TableIndex];
    return tableEntry->EnumerateObjects(req);
}
```

`NsiEnumerateObjectsAllParametersEx` does a lookup on NsiNpmList hoping to find the provider specified by the caller. It will find the `TcpInformationObject` of the requested module and execute the handler.

the NsiNpmList looks to belong to be a structure like this

```c
struct _NMP_MODULE{
    DWORD Length;
    DWORD Type; // set to 1 for the GUID
    DWORD Guid[4];
};

struct _NMP_CONTEXT{
    LIST_ENTRY *Flink;
    LIST_ENTRY *Blink;
    struct _NMP_MODULE *ModuleId;
    QWORD Unknown;
    QWORD* ProviderDispatch;
    QWORD* DispatchTable; // in TCP case it's TcpNsiInterfaceDispatch
};
```

for the TCP case the provider GUID is `{eb004a03-9b1a-11d4-9123-0050047759bc}`, I've found it on the 4th entry.

```
2: kd> dq ffffc48d`3bdf0178 <- this is the _NMP_CONTEXT entry
ffffc48d`3bdf0178  ffffc48d`3bdf0318 ffffc48d`3bddb4b8
ffffc48d`3bdf0188  fffff801`1dd89130 00000000`00000004
ffffc48d`3bdf0198  ffffc48d`3e5fecc0 fffff801`1ddc17a8 <- the dispatcher
ffffc48d`3bdf01a8  00000000`00000000 ffffc48d`3bdf7b5c
ffffc48d`3bdf01b8  ffffc48d`3b89cb80 00000001`00000002
ffffc48d`3bdf01c8  ffffc48d`3bdf01c8 ffffc48d`3bdf01c8
ffffc48d`3bdf01d8  ffffc48d`3e7fc388 ffffc48d`3bdf0210
ffffc48d`3bdf01e8  00000000`00000000 00000000`00000100

2: kd> dq fffff801`1dd89130
fffff801`1dd89130  00000001`00000018 11d49b1a`eb004a03 <- here is the guid
fffff801`1dd89140  bc597704`50002391 00000001`00000018
fffff801`1dd89150  11d49b1a`eb004a07 bc597704`50002391
fffff801`1dd89160  00000001`00000018 11d49b1a`eb004a0d
fffff801`1dd89170  bc597704`50002391 00000001`00000018
fffff801`1dd89180  11d49b1a`eb004a19 bc597704`50002391
fffff801`1dd89190  00000001`00000018 11d49b1a`eb004a1d
fffff801`1dd891a0  bc597704`50002391 00000001`00000018

2: kd> dq fffff801`1ddc17a8
fffff801`1ddc17a8  00000028`00100000 fffff801`1ddbf500 <- TcpInformationObject
fffff801`1ddc17b8  00000006`00100000 fffff801`1ddc0560 <- UdpInformationObject
fffff801`1ddc17c8  00000001`00100000 fffff801`1ddc0810 <- RawInformationObject
fffff801`1ddc17d8  00000000`00000000 ffffc48d`3bde3a10
fffff801`1ddc17e8  00000000`00000000 80000000`00000000
fffff801`1ddc17f8  00000000`00000000 00000001`00000000
fffff801`1ddc1808  00000000`000400ff fffff801`1ddc35a0
fffff801`1ddc1818  fffff801`1dd94a30 fffff801`1dd94a50

2: kd> dq fffff801`1ddbf500 + (0x68 * 3) + 0x40 L1 <- 4th entry, provided from UM
fffff801`1ddbf678  fffff801`1dcb5d80

2: kd> u fffff801`1dcb5d80
tcpip!TcpEnumerateAllConnections:
fffff801`1dcb5d80 4883ec28        sub     rsp,28h
fffff801`1dcb5d84 ba02000000      mov     edx,2
fffff801`1dcb5d89 e8f6020000      call    tcpip!TcpEnumerateConnectionType (fffff801`1dcb6084)
fffff801`1dcb5d8e 4883c428        add     rsp,28h
fffff801`1dcb5d92 c3              ret
```

We can see that GetTcpTable hardcoded the fourth entry for the kernel module to use it:

```c
ULONG GetTcpTable(PMIB_TCPTABLE TcpTable, PULONG SizePointer, BOOL Order)
{
 return GetTcpTableInternal(TcpTable, SizePointer, Order, 3, 0);
}
```

So far so good, we found the function responsible for fetching, `TcpEnumerateConnectionType(2)` is the call that is responsible for fetching the table data. `2` stands for `ENUMERATE_CONNECTIONS`, there are some other options available, which I would call them:

```c
enum _TCP_ENUMERATE_TYPE
{
    CONNECTIONS = 0,
    LISTENERS = 1,
    ALL = 2,
    BOUND_ENDPOINTS = 3
}
```

`TcpEnumerateConnectionType` is responsible for iterating the partition table, which consist of connections with the status of `ESTABLISHED_TCB`, `TIME_WAIT` and `SYN_TCB` (in memory order).

The pseudocode for this function looks like below:

```c
__int64 TcpEnumerateConnections(AF, KeyBuf, RwBuf, RoBuf, MaxEntries, *Count)
{
    AfObject = InetFindAndReferenceAf(&TcpInetTransport, AF);
    CompartmentId = NdisGetThreadObjectCompartmentId(KeGetCurrentThread());

    for (i = 0; i < PartitionCount; i++)
    {
        Partition = &PartitionTable[i]; 
        HashTables = Partition->HashTables;

        // established TCBs (hash table [0])
        RtlInitWeakEnumerationHashTable(&HashTables[0], &Enum);
        while (entry = RtlWeaklyEnumerateEntryHashTable(&HashTables[0], &Enum))
        {
            Tcb = entry - 0x28; // the size of hash table struct
            if (Tcb->Flags & 4 && Tcb->AF == AfObject && Tcb->Compartment == CompartmentId)
            {
                KeyBuf[*Count] = { LocalAddr, LocalPort, RemoteAddr, RemotePort};
                RwBuf[*Count]  = { PsGetProcessId(Tcb->Process), Timestamps };
                RoBuf[*Count]  = Tcb->State + 1;
            }
        }

        // SYN TCB (hash table [3])
        RtlInitWeakEnumerationHashTable(&HashTables[3], &Enum);
        while (entry = RtlWeaklyEnumerateEntryHashTable(&HashTables[3], &Enum))
        {
            SynTcb = entry - 0x10;
            if (SynTcb->Flags & 1 && SynTcb->AF == AfObject && SynTcb->Compartment == CompartmentId)
            {
                KeyBuf[*Count] = { LocalAddr, LocalPort, RemoteAddr, RemotePort };
                RwBuf[*Count]  = { PID, Timestamps = 0 };
                RoBuf[*Count]  = 4;   // SYN_RECEIVED
            }
        }

        // TIME_WAIT TCB (hash table [1])
        RtlInitWeakEnumerationHashTable(&HashTables[1], &Enum);
        while (entry = RtlWeaklyEnumerateEntryHashTable(&HashTables[1], &Enum))
        {
            TwTcb = entry;
            if (TwTcb->Active && TwTcb->AF == AfObject && TwTcb->Compartment == CompartmentId)
            {
                KeyBuf[*Count] = { LocalAddr, LocalPort, RemoteAddr, RemotePort};
                RwBuf[*Count]  = 0;
                RoBuf[*Count]  = 11;   // TIME_WAIT
            }
        }
    }
}
```

Overall the `_TCB` definition looks like this:

```c
typedef struct _IN_ADDR_DATA {
    ULONG       Address;
    PVOID       Next;
    ULONG_PTR   Flags;
} IN_ADDR_DATA, *PIN_ADDR_DATA;

typedef struct _LOCAL_ADDR_ENTRY {
    PIN_ADDR_DATA IpData;
    ULONG_PTR   Flags;
    PVOID       Next;
    PVOID       BackPtr;
} LOCAL_ADDR_ENTRY, *PLOCAL_ADDR_ENTRY;

typedef struct _INET_LOCAL_ADDR {
    ULONG_PTR   TagAndType;
    PVOID       Unknown0;
    PLOCAL_ADDR_ENTRY AddrEntry;
    ULONG_PTR   Unknown1;
} INET_LOCAL_ADDR, *PINET_LOCAL_ADDR;

typedef struct _TCP_ADDR_INFO {
    PINET_LOCAL_ADDR LocalAddr; 
    ULONG_PTR   LocalScopeFlags;
    PIN_ADDR_DATA RemoteAddr;
    ULONG       Flags;
    ULONG       Unknown;
} TCP_ADDR_INFO, *PTCP_ADDR_INFO;

typedef struct _TCB {
    KSPIN_LOCK  Lock;                   // 0x0
    PTCP_ADDR_INFO AddrInfo;            // 0x18
    RTL_DYNAMIC_HASH_TABLE_ENTRY HashEntry; // 0x28
    LONG RefCount;                      // 0x68
    ULONG       InternalState;          // 0x6C
    USHORT      LocalPort;              // 0x70
    USHORT      RemotePort;             // 0x72
    ULONG       ValidationFlags;        // 0x74  & 4 means valid
    UCHAR       LocalAddrType;          // 0x2B0
    UCHAR       RemoteAddrType;         // 0x2B1
    PEPROCESS   OwningProcess;          // 0x2D8
} TCB, *PTCB;
```

Now let's see this in action, let's enumerate IP addresses of live connections on WinDbg. 

First reference the `tcpip!PartitionTable`, first entry is the SPIN_LOCK so jump onto the second entry, it is the first hash table entry of type `_RTL_DYNAMIC_HASH_TABLE` 

```
2: kd> dt _RTL_DYNAMIC_HASH_TABLE poi(poi(tcpip!PartitionTable)+8)
ntdll!_RTL_DYNAMIC_HASH_TABLE
   +0x000 Flags            : 0
   +0x004 Shift            : 6
   +0x008 TableSize        : 0x80
   +0x00c Pivot            : 0
   +0x010 DivisorMask      : 0x7f
   +0x014 NumEntries       : 1
   +0x018 NonEmptyBuckets  : 1
   +0x01c NumEnumerators   : 0
   +0x020 Directory        : 0xffffc48d`3be0c010 Void

2: kd> dq 0xffffc48d`3be0c010
ffffc48d`3be0c010  ffffc48d`3be0c010 ffffc48d`3be0c010
ffffc48d`3be0c020  ffffc48d`3be0c020 ffffc48d`3be0c020
ffffc48d`3be0c030  ffffc48d`3be0c030 ffffc48d`3be0c030
ffffc48d`3be0c040  ffffc48d`3be0c040 ffffc48d`3be0c040
ffffc48d`3be0c050  ffffc48d`3be0c050 ffffc48d`3be0c050
ffffc48d`3be0c060  ffffc48d`3be0c060 ffffc48d`3be0c060
ffffc48d`3be0c070  ffffc48d`3be0c070 ffffc48d`3be0c070
ffffc48d`3be0c080  ffffc48d`3be0c080 ffffc48d`3be0c080
```

All of them point to the head, this means that buckets are empty. I kept doing this for a while and there are really a lot of buckets to check, we need a script to find a bucket with data.

```
.block {
    r $t0 = poi(poi(tcpip!PartitionTable) + 8)
    r $t1 = poi(@$t0 + 0x20)
    r $t2 = dwo(@$t0 + 0x08)
    .for (r $t3 = 0; @$t3 < @$t2; r $t3 = @$t3 + 1) {
        r $t4 = @$t1 + @$t3 * 0x10;
        r $t5 = poi(@$t4);
        .if (@$t5 != @$t4) {
            .printf "Bucket:%p\n", @$t5
        }
    }
}
```

Which gave me only one results `ffffc48d426d9a48` , this is the `PRTL_DYNAMIC_HASH_TABLE_ENTRY` inside a valid `TCB` struct, which holds the information about the connection that it's going to return back to usermode. 

Let's validate our findings:

```
1: kd> r $t7 = ffffc48d426d9a48 - 0x28

1: kd> dw @$t7 + 0x70 l2
ffffc48d`426d9a90  49c2 bb01 -> local port: 49737 and remote port: 443

1: kd> dw @$t7 + 0x6c l1
ffffc48d`426d9a8c  0004 -> status: ESTABLISHED
```

Ip addresses are a bit tricky because remote address dereference just doesn't make sense at the first look, but many connections can bind to the local address, which makes it a shared object stored far from the TCB.

```
1: kd> dq poi(poi(@$t7+0x18)+0x10) l1
ffffc48d`413feed0  00000000`b8854262 -> remote addr: 98.66.133.184


1: kd> dq poi(poi(poi(poi(@$t7+0x18))+0x10)) l1
ffffc48d`3bfe90c8  00000000`81e8a8c0 -> local addr: 192.168.232.129

1: kd> dq @$t7+0x2d8
ffffc48d`426d9cf8  ffffc48d`3ef30080 00000000`00000000
ffffc48d`426d9d08  01dc993a`0138eb89 00000000`00000102
ffffc48d`426d9d18  ffffc48d`411adc80 00000000`00000000
ffffc48d`426d9d28  ffffc48d`41229040 ffffc48d`42f16c40
ffffc48d`426d9d38  00000000`00000000 00000000`00000000
ffffc48d`426d9d48  00000000`00000000 00000000`00080008
ffffc48d`426d9d58  00000000`00000010 ffffc48d`426d9d68
ffffc48d`426d9d68  00000000`00000000 9e084b46`b0bee602

1: kd> dt nt!_EPROCESS UniqueProcessId
   +0x440 UniqueProcessId : Ptr64 Void

1: kd> dq ffffc48d`3ef30080 + 0x440 l1
ffffc48d`3ef304c0  00000000`00000bf4 -> PID: 3060
```

Time to confirm with netstat:

![](https://ibb.co/6c3L02JJ)

Here is a script that iterates and prints the connections inside those hash tables: [Enumerate TCP · GitHub](https://gist.github.com/xshiraori/c084ceb636f02616a549a3cb22ff0f39)


