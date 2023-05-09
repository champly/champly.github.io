---
title: 分布式系统
date: 2023-5-1 09:31:26
categories: Architecture
tags:
  - Distributed
  - Raft
---

> 该文档主要是 [mit 6.824](https://mit-public-courses-cn-translatio.gitbook.io/mit6-824) 课程的笔记以及一些扩展。

## Distributed Systems

### Drivens and Challenges

分布式系统的核心是通过网络来协调，共同完成一致任务的一些计算机。包括大型网站的存储系统、大数据运算(MapReduce)。*在设计一个系统时或者面对一个需要解决的问题时，如果可以在一台计算机上解决，而不需要分布式系统，那就应该用一台计算机解决问题。很多的工作都可以在一台计算机上完成，并且通常比分布式系统简单很多。所以，在选择使用分布式系统解决问题之前，应该充分尝试别的思路，因为分布式系统会让问题解决变得复杂。*

分布式系统会让问题的解决变得复杂，引入分布式系统的驱动力主要是：

- 需要获得更高的计算性能：大量的并行运算、大量 CPU、大量内存、以及大量磁盘在并行的运行；
- 可以提供容错(tolerate faults)。比如两台计算机运行完全相同的任务，其中一台发生故障，可以切换到另外一台；
- 有一些问题天然在空间上就是分布式的。例如银行转账，本身就分布在不通的低于，这就需要一种两者之间协调的方法，所以有一些天然的原因导致系统是物理分布的；
- 构建分布式系统来达成一些安全的目标。比如有一些代码并不被信任，但是有需要和它进行交互，这些代码不会立即表现的恶意或者出现 Bug。你不会想要信任这些代码，所以想要将代码分散在多处运行，这样你的代码在另外一台计算机运行，我的代码在我的计算机上运行，通过一些特定的网络协议通信。所以，我们可能会担心安全问题，我们把系统分成多个的计算机，这样可以限制出错域。

所有的这些分布式系统的问题在于：

- 因为系统中存在很多部分，这些部分又在并发执行，会遇到并发编程和各种复杂交互所带来的问题，以及时间依赖的问题（同步、异步）。这让分布式系统变得很难；
- 分布式系统有多个组成部分，再加上计算机网络，会遇到一些意想不到的故障。如果只有一台计算机，那么它通常要么是工作，要么是故障或者没电，总的来说，要么是在工作，要么是没有工作。而由多台计算机组成的分布式系统，可能会有一部分组件在工作，而另一部分组件停止运行，或者这些计算机都正常运行，但是网络中断或者不稳定。所以，局部错误也是分布式系统很难的原因；
- 人们设计分布式系统的根本原因通常是为了获得更高的性能，比如一千台计算机或者一千个磁盘能达到的性能。但是实际上一千台机器到底有多少性能是一个棘手的问题，这里有很多难点，所以通常需要加倍小心的设计才能让系统达到你期望的性能。

### Scalability

通常来说，构建分布式系统的目的是为了获取人们常常提到的可扩展的加速。所以，追求的是可扩展性。而这里说的可扩展或者可扩展性指的是，如果用一台计算机解决了一些问题，当买了第二台计算机，只需要一半的时间就可以解决这些问题。两台计算机构成的系统如果两倍性能或者吞吐，就是这里说的可扩展性。

我们希望可以通过增加机器的方式来实现扩展，但是现实中这很难实现，需要一些架构设计来将这个可扩展性无限推进下去。

### Availability

如果只使用一台计算机构建系统，那么大概率是可靠的，因为一台计算机通常可以很好的运行很多年，计算机是可靠的，操作系统是可靠的。所以一台计算机正常工作很长时间并不少见，然而如果通过数千台计算机构建系统，对于这么多计算机，也会有很大概率的故障。所以大型分布式系统中有一个大问题，就是一些很罕见的问题会被放大。对于容错，有很多不同的概念可以表述，这些表述中，有一个共同的思想就是可用性。某些系统经过精心的设计，可以在特定的错误类型下，系统仍然能够正常运行，仍然像没有出现错误一样，提供完整的服务。

除了可用性之外，另一种容错性是自我可恢复性(recoverability)。如果出现了问题，服务会停止工作，不再响应请求，之后有人来修复，并且在修复之后系统仍然可以正常运行，就像没有出现过问题一样。这是一个比可用性更弱的需求，因为在出现故障到故障组件被修复期间，系统将完全停止工作，但是修复之后，系统又可以完全正确的重新运行，所以可恢复性是一个重要的需求。对于一个可恢复的系统，通常需要做一些操作，例如将最新的数据存在磁盘中，这样恢复供电之后，才能将这些数据取回来等。为了实现这些特性，有很多工具。其中最重要的有两个：

- 非易失存储（non-volatile storage，类似磁盘）：这样当出现类似的电源故障，甚至整个机房电源故障，可以使用非易失存储。可以存放一些 checkpoint 或者系统状态的 log 在这些存储中，当故障修复之后，可以从硬盘中读出系统最新的状态，并从那个状态继续运行；
- 复制(replication)，不过，管理复制的多副本系统会有些棘手。任何一个多副本系统中，都会有一个关键问题，比如我们有两台服务器，本来运行着相同的系统状态，现在的关键问题在于，这两个副本总是会意外的偏离同步的状态，而不再互为副本。对于任何一种使用复制实现的容错系统，都会面临这个问题。

### Consistency

一致性就是用来定义操作行为的概念。之所以一致性是分布式系统中一个有趣的话题，是因为，从性能和容错的角度来说，我们通常会有多个副本。在一个非分布式系统中，通常只有一个服务器，一个表单。虽然不是绝对，但是通常来说对于 put/get 的行为不会有歧义。直观上来说，put 就是更新这个表单，get 就是从表单中获取当前表单中存储的数据，但是在分布式系统中，由于复制或者缓存，数据可能存在于多个副本当中，于是就有了多个不同版本的数据。

实际上，对于一致性有很多不同的定义。有一些非常直观，比如说 get 请求可以得到最近一次完成的 put 请求写入的值。这种一般也被成为强一致（Strong Consistency）。但是，事实上，构建一个弱一致的系统也是非常有用的。弱一致是指不保证 get 请求可以得到最近一次完成的 put 请求写入的值。虽然强一致可以确保 get 获取的是最新的数据，但是实现这一点代价非常高，几乎可以确定的是，分布式系统的各个组件需要做大量的通信，才能实现强一致性。

## CAP

CAP 理论对分布式系统的特性做了高度抽象，有三个指标：

- Consistency：一致性强调的不是数据完整，而是各个节点间对数据一致；
- Availability：可用性强调的是服务可用，但不保证数据的一致性；
- Partition Tolerance：分区容错性强调的是集群对分区故障的容错能力。

CAP 不可能都满足是对于一个分布式系统来说，只能在三个指标中选择其中两个。有网络交互就一定有延迟和数据丢失，而这种情况我们必须接受，还必须保证系统不能挂掉，所以 P 是必须要保证的，剩下的就只能在 C 和 A 中选一个。

## MapReduce

对于一个完整的 MapReduce Job，它由 Map Task 和一些 Reduce Task 组成:

- Job。整个 MapReduce 计算称为 Job；
- Task。每一次 MapReduce 调用称为 Task。


``` plantuml
@startuml mapreduce

actor developer
component master
storage output

node map1
node map2
node map3
node map4
node map5

node reduce1
node reduce2

developer ==> master: job

master -[dotted]-> map1
master -[dotted]-> map2
master -[dotted]-> map3
master -[dotted]-> map4
master -[dotted]-> map5

master -[dotted]-> reduce1
master -[dotted]-> reduce2

map1 --> reduce1
map1 --> reduce2
map2 --> reduce1
map2 --> reduce2
map3 --> reduce1
map3 --> reduce2
map4 --> reduce1
map4 --> reduce2
map5 --> reduce1
map5 --> reduce2

reduce1 --> output
reduce2 --> output

@enduml
```

MapReduce 展示了一个分布式系统的可扩展性。

## Replication

容错本身是为了提高可用性，当想构建一个服务时，尽管计算机硬件总是有可能故障，但是我们还是希望能稳定的提供服务，甚至出现了网络问题我们还是想能够提供服务。使用到的工具就是复制。最简单的方法来描述复制能处理的故障，就是单台计算机的 fail-stop 故障。不能解决软件中的 Bug 和硬件设计中的缺陷，还有另外一种情况，比如自然灾害，摧毁了整个数据中心，无论有多少副本都无济于事。如果我们想处理类似的问题，就需要将副本放在不同的城市，或者物理上把它们分开（同城双活、两地三中心架构）。另一个有关复制的问题是，这种复制的方案是否值得？这个不是一个可从技术上来回答的问题，这是一个经济上的问题，取决于一个可用服务的价值。

> 所以任何技术都不是银弹，都是需要根据实际情况进行抉择和取舍。

### State Transfer

状态转移背后的思想是，Primary 将自己完整状态，比如内存中的内容，拷贝并发送给 Backup。Backup 会保存收到的最近一次状态，所以 Backup 会有所有的数据。当 Primary 故障了，Backup 就可以从它所保存的最新状态开始运行。所以，状态转移就是发送Primary 的状态。

### Replicated State Machine

复制状态机基于这个事实：我们想复制的大部分的服务或者计算机软件都有一些确定的内部操作，不确定的部分是外部输入。通常情况下，如果一台计算机没有外部影响，它只是一个接一个的执行命令，每条指令执行的是计算机中的内存和寄存器上的确定函数，只有当外部事件干预时，才会发生一些预期之外的事。例如某个随机事件收到了一个网络数据包，导致服务做了一些不同的事情。所以，复制状态机不会在不同的副本之间发送状态，相应的，它只会从 Primary 将这些外部事件，例如外部的输入，发送给 Backup。通常来说，如果有两台计算机，如果他们从相同的状态开始，并且它们以相同的顺序，在相同的事件，看到了相同的输入，那么它们会一直互为副本，并且保持一致。

> 所以状态转移传输的可能是内存，而复制状态机会将来自客户端的操作或者其他外部事件，从 Primary 传输到 Backup。

人们倾向于使用复制状态机的原因是，通常来说，外部操作或者事件比服务的状态要小。

## Raft

### Split Brain

尽管存在脑裂的可能，但是随着技术的发展，人们发现就算网络出现故障，可能出现分区，实际上是可以正确的实现能够自动完成故障切换的系统。当网络出现故障，将网络分割成两半，网络的两边独立运行，且不能访问对方，这通常被称为网络分区。在构建能自动恢复，同时又避免脑裂的多副本系统时，人们发现，关键点在于过半票决（Majority Vote）。

过半票决系统第一步在于，服务器的数量要是奇数，而不是偶数。在任何时候为了完成任何操作，必须凑够过半的服务器来批准相应的操作。

> 如果系统有 2*F + 1 个服务器，那么系统最多可以接受 F 个服务器出现故障，仍然可以正常工作。

[raft 共识算法动画演示](http://www.kailing.pub/raft/index.html)

### AppendEntries

``` plantuml
@startuml raft-log

actor Client
participant Leader
participant Follower1
participant Follower2

Client --> Leader : request
group raft
    group AppendEntries
        Leader --> Follower1 : AppendEntries
        Leader --> Follower2 : AppendEntries
        Follower1 --> Leader : Ack
        Follower2 --> Leader : Ack

        Leader --> Leader : Wait
        note right #FFAAAA
            等待过半节点响应（包括自己），这里只需要等待一个 Follower 响应
        end note
    end

    Leader --> Client : response
    note right
    和 commit 流程同步执行，如果有过半节点响应，则返回成功，同时执行 commit 逻辑
    如果没有过半节点响应，则返回失败，不执行 commit 逻辑
    end note

    group commit
        Leader --> Follower1 : AppendEntries
        Follower1 --> Follower1 : judge commit ID
        note right
            Leader 会将更大的 commit ID 发送给 Follower，
            当其他副本收到了这个消息就知道之前提交的 commit 号已经被 Leader 提交
        end note
        Leader --> Follower2 : AppendEntries
        Follower2 --> Follower2 : judge commit ID
    end
end

@enduml
```

### Leader Election

``` plantuml
@startuml leader-election

state Follower
state Candidate
state Leader

[*] -> Follower : 初始状态
Follower --> Candidate : 超时，开始选举
Candidate --> Candidate : 超时，进行新一轮选举
Candidate --> Leader : 收到过半服务的投票
Leader --> Follower : 收到更高的任期(term)
Candidate --> Follower : 出现 Leader 或者出现更高的任期(term)

@enduml
```

- 系统启动时，默认都是 Follower 状态，初始化时会随机赋予一个时间(150~300ms)，当超时之后会转换为 Candidate 状态，发起一轮投票；
- Candidate 是选主过程中的中间状态，只有大多数 Follower 投票通过时，才会转换为 Leader；
- 如果 Candidate 选主超时，则会发起新一轮选主过程（当前 term 会加一）；
- 如果 Candidate 收到 Leader 发来的信息时，会转换为 Follower；
- Follower 在一个任期（term）过程中，只会给一个 Candidate 投票，投票之后会重置超时时间；
- Candidate 和 Leader 在发现更大的任期时，都会转换为 Follower。

### Election Restriction

Follower 只能向满足下面条件之一的 Candidate 投票:

- Candidate 最后一条 Log 条目的任期号大于本地最后一条 Log 条目的任期号；
- Candidate 最后一条 Log 条目的任期号等于本地最后一条 Log 条目的任期号，并且 Candidate 的 Log 长度大于或等于本地 Log 记录的长度。

### Log Backup

Leader 中的日志只能追加，Leader 会强制让 Follower 的数据和自己保持一致。Leader 为每个 Follower 维护了 nextIndex，nextIndex 的初始值是从新任的最后一条日志开始。AppendEntries 消息包含了 prevLogIndex 和 prevLogTerm 字段，这样的 AppendEntries 消息发送给了 Follower。而 Follower 它们在收到 AppendEntries 消息时，可以知道它们收到一个带有若干 Log 条目的消息，Follower 在写入 Log 之前，会检查本地的前一个 Log 条目，是否与 Leader 发来的 prevLogIndex 信息匹配。如果不匹配，Followers 会拒绝。为了响应 Follower 返回的拒绝，Leader 会减少对应的 nextIndex，直到匹配，才会把数据写入本地（新增或者修改）。

这样一个一个回退的过程太慢了，可以让 Follower 在返回消息的时候多返回一些信息，就可以加速恢复：

- XTerm：这个是 Follower 中与 Leader 冲突的 Log 对应的任期号，如果 Follower 在对应位置的任期号不匹配，它会拒绝 Leader 的 AppendEntries 消息，并将自己的任期号放在 XTerm 中。如果 Follower 在对应位置没有 Log，那么会返回 -1；
- XIndex：这个是 Follower 中，对应任期号为 XTerm 的第一条 Log 条目的槽位号；
- XLen：如果 Follower 在对应位置没有 Log，那么 XTerm 会返回 -1，XLen 表示空白的 Log 槽位数。

还可以通过日志快照（Log Snapshot）的方式来快速恢复：当 Follower 刚恢复，如果它的 Log 已经很滞后了，那么它会首先强制 Leader 回退自己的 Log，在某个点，Leader 将不能再回退，因为已经到了自己 Log 的起点，这个时候 Leader 会将自己的快照发给 Follower，滞后立即通过 AppendEntries 将后面的 Log 发给 Follower。

## Linearizability

通常来说，线性一致等价于强一致，一个服务是线性一致的，那么它表现的就像只有一个服务器，并且服务器没有故障，这个服务器每次执行一个客户端请求，并且没有什么奇怪的事情发生。要达到线性一致性，我们现在要确定顺序，对于这个顺序，有两个限制条件：

- 如果一个操作在另一个操作开始前就结束了，那么这个操作必须在执行历史中出现在另一个操作前面；
- 执行历史中，读操作，必须在相应的 key 的写操作之后。

如果我们能构建这么一个序列，那么可以证明，这里的请求历史记录是线性的，必须同时满足：

- 序列中的请求的顺序与实际时间匹配；
- 每个读请求看到的都是序列中前一个写请求写入的值。

## Zookeeper

相比 Raft 来说，Raft 实际上就是一个库。可以在更大的多副本系统中使用 Raft 库。但是 Raft 不是一个你可以直接交互的独立服务，你必须要设计你自己的应用程序来与 Raft 库交互。Zookeeper 作为一个多副本系统，是一个容错的、通用的协调服务，它与其他系统一样，通过多副本来完成容错。

Zookeeper 和 Raft 类似，先发出 Log 条目之后，当 Leader 收到了过半服务器当回复，Leader 就会发送 commit 消息。Zookeeper 的读性能随着服务器数量的增加而显著的增加。所以很明显，Zookeeper 在这里有一些修改使得读请求可以由其他副本来处理。那么 Zookeeper 是如何确保这里的读请求是安全的（线性一致）？

实际上，Zookeeper 并不要求返回最新的写入数据。Zookeeper 的方式是，放弃线性一致性，不提供线性一致的读。所以 Zookeeper 也不用为读请求提供最新的数据，它由自己有关一致性的定义，而这个定义不是线性一致的，因此允许读请求返回旧的数据。所以 Zookeeper 这里声明自己最开始就不支持线性一致性，来解决这里的技术问题。如果不提供这个能力，那么读请求返回旧的数据。这里实际上是一种经典的解决性能和强一致之间矛盾的方法，也就是不提供强一致。

这里的工作原理是，每个 Log 条目都会被 Leader 打上 zxid 的标签，这些标签就是 Log 对应的条目号。任何时候一个副本回复一个客户端的读请求，首先这个读请求是在 Log 的某个特定点执行的，其次回复里面会带上 zxid，对应的就是 Log 执行点的前一条 Log 条目。客户端会记住最高 zxid，当客户端发出一个请求到一个相同或者不同的副本时，它会在它的请求中带上这个最高的 zxid。这样，其他副本就知道，应该至少在 Log 中这个点或者之后执行读请求。那么在获取到对应这个位置的 Log 之前，这个副本是不能响应客户端请求。

## Quorum Replication

假设由 N 个副本，为了能够执行写请求，必须要确保写操作被 W 个副本确认，W 小于 N。所以你需要将写入请求发送到这 W 个副本。如果要执行读请求，那么至少需要从 R 个副本得到所读取的信息。这里的 W 对应的数字成为 Write Quorum，R 对应的数字成为 Read Quorum。Quorum 系统要求，任意你要发送写请求的 W 个服务器，必须与任意接受读取请求的 R 个服务器由重叠。意味着，`R + W` 必须大于 N（至少满足 `R + W = N + 1`）。这样任意 W 个服务器至少与任意 R 个服务器有一个重合。

还有一个关键点，客户端读取请求可能会得到 R 个不同的结果，需要通过最高版本号（Version）的数值作为结果。当 R 为 1 时，写请求就不再是容错的了，W 为 1 时，读请求不再是容错的，都必须要求所有的服务器在线。

> 可以通过调整 W 和 R 来提升服务的写性能或者读性能。

## Distributed Transaction

可以这么理解事务：程序员有一些不同的操作，或许针对数据库不同记录，他们希望所有这些操作作为一个整体，不会因为失败而被分割，也不会被其他活动看到中间状态。事务处理系统要求程序员对这些读操作、写操作标明起始和结束，这样才能知道事务起始和结束。事务处理系统可以保证在事务的开始和结束之间的行为是可预期的。数据库通常对于正确性有一个概念称为 ACID:

- Atomic，原子性。意味着事务可能有多个步骤，比如写多个数据记录，尽管可能存在故障，但是要么所有的写数据都完成了，要么没有写数据能完成。不应该发生类似的这种情况：在一个特定的时间发生了故障，导致事务中一半的写数据完成并可见，另一半的写数据没有完成，这里要么全有，要么全没有（All or Nothing）；
- Consistent，一致性。它通常是指数据库会强制某些应用程序定义的数据不变；
- Isolated，隔离性。这是一个属性，表明两个同时运行的事务，在事务结束前，能不能看到彼此的更新，能不能看到另一个事务中间的临时的更新。目标是不能，隔离在技术上的具体体现是，事务需要串行执行。事务不能看到彼此之间的中间状态，只能看到完成的事务结果；
- Durable，持久化。意味着在事务提交之后，数据库中的修改是持久化的，不会应为一些错误而被擦除。这意味着数据要被写入到一些非易失的存储（Non-Volatile Storage），持久化的存储，例如磁盘。

通常来说，隔离性意味着可序列化（Serializable）。它的定义是如果在同一时间并行的事务，那么可以生成一系列的结果。这里的结果包含：

- 由任何事务中的修改行为产生的数据库记录的修改；
- 任何事务生成的输出。

我们说可序列化是指，并行的执行一些事务得到的结果，与按照某种串行的顺序来执行这些事务，可以得到相同的结果。实际的执行过程或许有大量的并行处理，但是这里要求得到的结果与按照某种顺序一次一个事务的串行执行结果是一样的。所以，如果检查一个并发事务执行是否是可序列化的，可以查看结果，并看看是否可以找到对于同一些事务，存在一次只执行一个事务的顺序，按照这个顺序执行可以生成相同的结果。

> 现实中隔离性要看数据库配置的隔离级别。

### Concurrency Control

在并发控制中，主要有两种策略:

- 悲观并发控制（Pessimistic Concurrency Control）: 在事务使用任何数据之前，它需要获得数据的锁，如果有一些其他的事务已经在使用这里的数据，锁会被它们持有，当前事务必须等待这些事务结束，之后当前事务才能获取到锁。在悲观系统中，如果由锁冲突，就会造成延时等待；
- 乐观并发控制（Optimistic Concurrency Control）: 基本思想是，你不用担心其他事务是否正在读写你要使用的数据，你直接继续执行你的读写操作，通常来说这些执行会在一些临时区域，只有在事务最后的时候，再检查是不是有一些其他事务干扰了你。如果没有就可以完成事务，并且不需要承受锁带来的性能损耗，因为操作锁的代价一般都比较高；如果有一些其他的事务在同一时间修改了你关心的数据，造成了冲突，那么就必须 Abort 掉当前事务，并重试。

具体使用哪种策略应该取决于不同的环境，如果冲突非常频繁，或许用悲观并发控制更好一些。悲观控制的锁就是两阶段锁（Two-Phase Locking）。

### Two-Phase Commit

``` plantuml
@startuml two-phase commit

actor Client
participant TC
participant A
participant B
participant C

group operator
    TC --> A : get
    TC --> B : set
    TC --> C : set
    ... multi operator ...
end

group prepare
    TC --> A : Prepare
    A --> TC : Yes/No
    TC --> B : Prepare
    B --> TC : Yes/No
    TC --> C : Prepare
    C --> TC : Yes/No
end

alt #LightGreen 所有的结果都返回 Yes
    group commit
        TC --> TC : Commit(WAL)
        TC --> Client : Response Commit
        group loop
            TC --> A : Commit
            A --> TC : Ack
        end
        group loop
            TC --> B : Commit
            B --> TC : Ack
        end
        group loop
            TC --> C : Commit
            C --> TC : Ack
        end
    end
else #Pink 至少有一个结果返回 No
    group abort
        TC --> TC : Abort(WAL)
        TC --> Client : Response Abort
        group loop
            TC --> A : Abort
            A --> TC : Ack
        end
        group loop
            TC --> B : Abort
            B --> TC : Ack
        end
        group loop
            TC --> C : Abort
            C --> TC : Ack
        end
    end
end

@enduml
```

有一些关键点：

- 一旦回复 Prepare 消息为 Yes 之后，就不能结束事务，必须等待 TC 进行协调；回复 No 之后可以直接 Abort 掉本地事务;
- 本地没有对应的 Abort 事务也要返回 Ack 信息。

---

参考链接:

[https://sineyuan.github.io/post/etcd-raft-source-guide/](https://sineyuan.github.io/post/etcd-raft-source-guide/)
[https://github.com/etcd-io/raft](https://github.com/etcd-io/raft)
[https://raft.github.io/](https://raft.github.io/)
[https://github.com/goraft/raft](https://github.com/goraft/raft)
[https://github.com/hashicorp/raft](https://github.com/hashicorp/raft)
[https://zhuanlan.zhihu.com/p/49792009](https://zhuanlan.zhihu.com/p/49792009)
[http://www.zhaowenyu.com/etcd-doc/introduction/what-is-raft.html](http://www.zhaowenyu.com/etcd-doc/introduction/what-is-raft.html)
[https://zhuanlan.zhihu.com/p/91288179](https://zhuanlan.zhihu.com/p/91288179)
[https://docs.qq.com/doc/DY0VxSkVGWHFYSlZJ?_t=1609557593539](https://docs.qq.com/doc/DY0VxSkVGWHFYSlZJ?_t=1609557593539)
[https://www.open-open.com/lib/view/open1328763454608.html](https://www.open-open.com/lib/view/open1328763454608.html)
[https://ms2008.github.io/2019/12/04/etcd-rumor/](https://ms2008.github.io/2019/12/04/etcd-rumor/)
[https://zhuanlan.zhihu.com/p/152105666](https://zhuanlan.zhihu.com/p/152105666)
[https://zhuanlan.zhihu.com/p/524885008](https://zhuanlan.zhihu.com/p/524885008)
[https://t1mek1ller.github.io/2018/03/01/raft/](https://t1mek1ller.github.io/2018/03/01/raft/)
