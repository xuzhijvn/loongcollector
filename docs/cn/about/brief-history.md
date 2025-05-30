# 发展历史

LoongCollector 原名 iLogtail ，从 2013 年开始研发，于 2024 年 iLogtail 开源项目两周年庆典之际，品牌正式升级为 LoongCollector。

## iLogtail 阶段

秉承着阿里人简单的特点， iLogtail 的命名也非常简单，我们最开始期望的就是能够有一个统一去Tail日志的工具，所以就叫做Logtail，添加上“i”的原因主要当时使用了inotify的技术，能够让日志采集的延迟控制在毫秒级，因此最后叫做 iLogtail。iLogtail 整个发展历程概括起来大致可以分为四个阶段，分别是飞天5K阶段、阿里集团阶段、云原生阶段和开源共建阶段。

![iLogtail 发展历史](<https://ilogtail-community-edition.oss-cn-shanghai.aliyuncs.com/images/readme/ilogtail-history.png>)

### 飞天5K阶段 <a href="#4ever-bi-127" id="4ever-bi-127"></a>

作为中国云计算领域的里程碑，2013年8月15日，阿里巴巴集团正式运营服务器规模达到5000（5K）的“飞天”集群，成为中国第一个独立研发拥有大规模通用计算平台的公司，也是世界上第一个对外提供5K云计算服务能力的公司。飞天5K项目从2009年开始，从最开始的30台逐渐发展到5000，不断解决系统核心的问题，比如说规模、稳定性、运维、容灾等等。而 iLogtail 在这一阶段诞生，最开始就是要解决5000台机器的监控、问题分析、定位的工作（如今的词语叫做“可观测性”）。从30到5000的跃升中，对于可观测问题有着诸多的挑战，包括单机瓶颈、问题复杂度、排查便捷性、管理复杂度等。

在5K阶段， iLogtail 本质上解决的是从单机、小规模集群到大规模的运维监控挑战，这一阶段 iLogtail 主要的特点有：

* 功能：实时日志、监控采集，日志抓取延迟毫秒级
* 性能：单核处理能力10M/s，5000台集群平均资源占用0.5%CPU核
* 可靠性：自动监听新文件、新文件夹，支持文件轮转，处理网络中断
* 管理：远程Web管理，配置文件自动下发
* 运维：加入集团yum源，运行状态监控，异常自动上报
* 规模：3W+部署规模，上千采集配置项，日10TB数据

### 阿里集团阶段 <a href="#4ever-bi-265" id="4ever-bi-265"></a>

iLogtail 在阿里云飞天5K项目中的应用解决了日志、监控统一收集的问题，而当时阿里巴巴集团、蚂蚁等还缺少一套统一、可靠的日志采集系统，因此我们开始推动 iLogtail 作为集团、蚂蚁的日志采集基础设施。从5K这种相对独立的项目到全集团应用，不是简单复制的问题，而我们要面对的是更多的部署量、更高的要求以及更多的部门：

1. 百万规模运维问题：此时整个阿里、蚂蚁的物理机、虚拟机超过百万台，我们希望只用1/3的人力就可以运维管理百万规模的Logtail
2. 更高的稳定性： iLogtail 最开始采集的数据主要用于问题排查，集团广泛的应用场景对于日志可靠性要求越来越高，例如计费计量数据、交易数据，而且还需要满足双十一、双十二等超大数据流量的压力考验。
3. 多部门、团队：从服务5K团队到近千个团队，会有不同的团队使用不同的 iLogtail ，而一个 iLogtail 也会被多个不同的团队使用，在租户隔离上对 iLogtail 是一个新的挑战。

经过几年时间和阿里集团、蚂蚁同学的合作打磨， iLogtail 在多租户、稳定性等方面取得了非常大的进步，这一阶段 iLogtail 主要的特点有：

* 功能：支持更多的日志格式，例如正则、分隔符、JSON等，支持多种日志编码方式，支持数据过滤、脱敏等高级处理
* 性能：极简模式下提升到单核100M/s，正则、分隔符、JSON等方式20M/s+
* 可靠性：采集可靠性支持Polling、轮转队列顺序保证、日志清理保护、CheckPoint增强；进程可靠性增加Critical自恢复、Crash自动上报、多级守护
* 多租户：支持全流程多租户隔离、多级高低水位队列、采集优先级、配置级/进程级流量控制、临时降级机制
* 运维：基于集团StarAgent自动安装与守护，异常主动通知，提供多种问题自查工具
* 规模：百万+部署规模，千级别内部租户，10万+采集配置，日采集PB级数据

### 云原生阶段 <a href="#4ever-bi-329" id="4ever-bi-329"></a>

随着阿里所有IT基础设施全面云化，以及 iLogtail 所属产品[SLS](https://www.aliyun.com/product/sls)（日志服务）正式在阿里云上商业化， iLogtail 开始全面拥抱云原生。从阿里内部商业化并对外部各行各业的公司提供服务，对于 iLogtail 的挑战的重心已经不是性能和可靠性，而是如何适应云原生（容器化、K8s，适应云上环境）、如何兼容开源协议、如何去处理碎片化需求。这一阶段是 iLogtail 发展最快的时期，经历了非常多重要的变革：

* 统一版本： iLogtail 最开始的版本还是基于GCC4.1.2编译，代码还依赖飞天基座，为了能适用更多的环境， iLogtail 进行了全版本的重构，基于一套代码实现Windows/Linux、X86/Arm、服务器/嵌入式等多种环境的编译发版
* 全面支持容器化、K8s：除了支持容器、K8s环境的日志、监控采集外，对于配置管理也进行了升级，支持通过Operator的方式进行扩展，只需要配置一个AliyunLogConfig的K8s自定义资源就可以实现日志、监控的采集
* 插件化扩展： iLogtail 增加插件系统，可自由扩展Input、Processor、Aggregator、Flusher插件用以实现各类自定义的功能
* 规模：千万部署规模，数万内外部客户，百万+采集配置项，日采集数十PB数据

### 开源共建阶段

闭源自建的软件永远无法紧跟时代潮流，尤其在当今云原生的时代，我们坚信开源才是 iLogtail 最优的发展策略，也是释放其最大价值的方法。 iLogtail 作为可观测领域最基础的软件，我们将之开源，也希望能够和开源社区一起共建，持续优化，争取成为世界一流的可观测数据采集器。对于未来iLogail的发展，我们期待：

1. iLogtail 在性能和资源占用上相比其他开源采集软件具备一定优势，相比开源软件，在千万部署规模、日数十PB数据的规模性下为我们减少了100TB的内存和每年1亿的CPU核小时数。我们也希望这款采集软件可以为更多的企业带来资源效率的提升，实现可观测数据采集的“共同富裕”。
2. 目前 iLogtail 还只是在阿里内部以及很小一部分云上企业在使用，面对的场景相对还较少，我们希望有更多不同行业、不同特色的公司可以使用 iLogtail 并对其提出更多的数据源、处理、输出目标的需求，丰富 iLogtail 支持的上下游生态。
3. 性能、稳定性是 iLogtail 的最基本追求，我们也希望能够通过开源社区，吸引更多优秀的开发者，一起共建 iLogtail ，持续提升这款可观测数据采集器的性能和稳定性。

## LoongCollector 阶段

**品牌寓意：** LoongCollector，灵感源于东方神话中的“中国龙”形象，Logo 中两个字母 O 犹如龙灵动的双眼，充满灵性。龙的眼睛具有敏锐的洞察力，正如 LoongCollector 能够全面精准地采集和解析每一条可观测数据；龙的灵活身躯代表了对多变环境高度的适应能力，映射出 LoongCollector 广泛的系统兼容性与灵活的可编程性，可以满足各种复杂的业务需求；龙的强大力量与智慧象征了在高强度负载下卓越的性能和无与伦比的稳定性。最后，期待 LoongCollector 犹如遨游九天的中国龙，不断突破技术边界，引领可观测采集的新高度。

**定位：** LoongCollector 是一款集卓越性能、超强稳定性和灵活可编程性于一身的数据采集器，专为构建下一代可观测 Pipeline 设计。

**愿景：** 打造业界领先的“统一可观测 Agent（Unified Observability Agent）”与“端到端可观测 Pipeline（End-to-End Observability Pipeline）”。

LoongCollector 的品牌进化，不仅仅是技术上的革新，更是我们对开源精神与技术远见的全面诠释与坚定承诺。
