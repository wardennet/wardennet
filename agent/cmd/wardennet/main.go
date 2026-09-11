// Package main 是 WardenNet Agent 的主入口。
// Phase 1 实现：串联 logparser → detector → ipset → ttl → snapshot → unixsocket 全链路。
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wardennet/agent/internal/cli"
	"github.com/wardennet/agent/internal/cloudsync"
	"github.com/wardennet/agent/internal/config"
	"github.com/wardennet/agent/internal/detector"
	"github.com/wardennet/agent/internal/ipsetutil"
	"github.com/wardennet/agent/internal/logger"
	"github.com/wardennet/agent/internal/logparser"
	"github.com/wardennet/agent/internal/pidlock"
	"github.com/wardennet/agent/internal/plugin"
	"github.com/wardennet/agent/internal/portscan"
	"github.com/wardennet/agent/internal/snapshot"
	"github.com/wardennet/agent/internal/stats"
	"github.com/wardennet/agent/internal/threatreporter"
	"github.com/wardennet/agent/internal/ttl"
	"github.com/wardennet/agent/internal/unixsocket"
)

// Version 编译期注入，默认 dev。
var Version = "dev"

func main() {
	// 初始化随机种子（SyncEngine jitter 需要）
	rand.Seed(time.Now().UnixNano())

	// 检测是否为 CLI 子命令模式（在 flag.Parse 之前，避免 unknown flag 报错）
	if isCLIMode(os.Args[1:]) {
		os.Exit(runCLI(os.Args[1:]))
	}

	configPath := flag.String("config", "/etc/wardennet/config.yaml", "path to wardennet config yaml")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("wardennet agent %s\n", Version)
		return
	}

	// 记录启动时间（用于 uptime 计算）
	startTime := time.Now()

	// 1. 加载配置
	loader := config.NewLoader(*configPath)
	if err := loader.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
		os.Exit(1)
	}
	cfg, err := loader.Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "get config: %v\n", err)
		os.Exit(1)
	}

	// 2. 初始化日志器
	logCfg := logger.LogConfig{
		Level:      cfg.Log.Level,
		File:       cfg.Log.File,
		MaxSize:    cfg.Log.MaxSize,
		MaxBackups: cfg.Log.MaxBackups,
		MaxAge:     cfg.Log.MaxAge,
		Compress:   cfg.Log.Compress,
	}
	lg, err := logger.New(logCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer lg.Close()

	// 2.5 获取单实例锁（在任何副作用初始化之前）
	// 另一个 agent 进程存活时直接退出，避免两个进程同时写 iptables/ipset/snapshot/log tail。
	// kill -9 不会清理 PID 文件，但内核 flock 会自动释放，下次启动能正常 Acquire。
	pidLock, err := pidlock.Acquire()
	if err != nil {
		// logger 已可用，同时写 stderr 和日志
		lg.Error("cannot acquire instance lock", "err", err)
		fmt.Fprintf(os.Stderr, "wardennet: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if rerr := pidLock.Release(); rerr != nil {
			lg.Error("failed to release pid lock", "err", rerr)
		}
	}()
	lg.Info("single-instance lock acquired", "pid_file", pidLock.Path())

	lg.Info("wardennet agent starting",
		"version", Version,
		"config", *configPath,
		"log_sources", len(cfg.LogSources),
	)

	// 3. 初始化 ipset 管理器（Linux 用真实 ipset，其他平台用内存 Mock）
	ipClient := newIPSetClient()
	ipMgr := ipsetutil.NewManager(ipClient, 3, 100*time.Millisecond)
	defer ipMgr.Close()

	// 从内核 ipset 重建 blocked 内存 map（上次运行遗留的条目）
	if count, err := ipMgr.RebuildFromKernel(); err != nil {
		lg.Warn("rebuild blocked from kernel failed (ok on first start)", "err", err)
	} else {
		lg.Info("rebuild blocked from kernel", "count", count)
	}

	// Linux 平台初始化 iptables 封禁规则
	platformInit(lg)

	// 加载本地白名单配置
	if len(cfg.IPSet.Whitelist) > 0 {
		if err := ipMgr.SyncLocalWhitelist(cfg.IPSet.Whitelist); err != nil {
			lg.Warn("sync local whitelist failed", "err", err)
		} else {
			lg.Info("local whitelist loaded", "count", len(cfg.IPSet.Whitelist))
		}
	}

	// 加载本地黑名单配置（断网兜底）
	for _, ip := range cfg.IPSet.Blacklist {
		if accepted, err := ipMgr.Block(ip); err != nil {
			lg.Warn("preload blacklist failed", "ip", ip, "err", err)
		} else if accepted {
			lg.Info("preloaded blacklist ip", "ip", ip)
		}
	}

	// 4. 初始化 TTL 管理器
	ttlCfg := mapTTLConfig(cfg.Agent)
	// 让 ipMgr 在本地 block 时自动带 --timeout，内核到期自动清除（第一层兜底）
	ipMgr.SetBlockTimeout(ttlCfg.LocalBlockTTL)
	lg.Info("ipset blacklist kernel timeout enabled", "seconds", ttlCfg.LocalBlockTTL)
	// onExpire 回调：Sweep 时自动调 ipMgr.Unblock（第二层兜底，与内核 timeout 双重冗余）
	ttlMgr := ttl.NewManager(ttlCfg, func(entries []ttl.Entry) {
		for _, e := range entries {
			// SourceCloud：syncEngine.applyDecisions 注册的云端 BLOCK（含联防快速通道）
			// SourceLocal：detector.BlockTrigger 注册的本地 BLOCK（已在下面加了 INFO 日志）
			if err := ipMgr.Unblock(e.IP); err != nil {
				lg.Warn("auto-unblock failed", "ip", e.IP, "err", err)
			} else {
				srcTag := "local"
				if e.Source == ttl.SourceCloud {
					srcTag = "cloud"
				}
				lg.Info("auto-unblock expired", "ip", e.IP, "ttl_source", srcTag)
			}
		}
	})
	defer ttlMgr.Close()

	// 5. 初始化统计收集器（采样率：100=每 100 条记录 1 条用于分析）
	statsCollector := stats.NewCollector(100)
	lg.Info("stats collector initialized", "sample_rate", 100)

	// 5.1 初始化滑动窗口检测引擎
	// 白名单直接复用 ipMgr（ipsetutil.Manager），Go duck typing 自动满足 detector.WhitelistChecker。
	// 好处：Detector 和 Manager 共享同一份 localWL/localWLCIDR——
	//       云端租户下发的 WhiteAdd/WhiteDel 只更新 Manager，但 Detector 也实时感知到了。
	detCfg := mapDetectorConfig(cfg.Detector)
	det := detector.NewLocalDetector(&detCfg, ipMgr)
	defer det.Close()

	// 5.2 设置详情日志记录器（score_low 以下不进统计不打 debug）
	det.SetDetailLogger(&detDetailLogger{lg: lg, stats: statsCollector, scoreLow: detCfg.ScoreLow})

	// v1.0 注入可选增强模块
	// BodyScanner（请求体扫描 + 文件上传拦截）
	if cfg.Detector.BodyScan.Enabled {
		bsCfg := cfg.Detector.BodyScan
		bs := detector.NewBodyScanner(
			true,
			bsCfg.MaxBodySize,
			detCfg.DangerousPatterns,
			bsCfg.FileUpload.BlockedExtensions,
			bsCfg.FileUpload.BlockedMimeTypes,
			bsCfg.ContentTypes,
		)
		det.SetBodyScanner(bs)
		lg.Info("body scanner enabled",
			"max_size", bsCfg.MaxBodySize,
			"content_types", len(bsCfg.ContentTypes),
			"blocked_exts", len(bsCfg.FileUpload.BlockedExtensions),
		)
	} else {
		lg.Info("body scanner disabled (body_scan.enabled=false)")
	}

	// ResourceBaseline（IDOR/BOLA 越权检测）
	if cfg.Detector.ResourceBaseline.Enabled {
		patterns := make([]detector.ResourcePattern, 0, len(cfg.Detector.ResourceBaseline.Patterns))
		for _, p := range cfg.Detector.ResourceBaseline.Patterns {
			patterns = append(patterns, detector.ResourcePattern{
				PathRegex: p.PathRegex,
				IDRegex:   p.IDRegex,
				WindowSec: p.WindowSec,
				MaxIDs:    p.MaxIDs,
				Weight:    p.Weight,
			})
		}
		rb := detector.NewResourceBaseline(true, patterns)
		det.SetResourceBaseline(rb)
		lg.Info("resource baseline (IDOR) enabled", "patterns", len(patterns))
	} else {
		lg.Info("resource baseline (IDOR) disabled (resource_baseline.enabled=false)")
	}

	// 注册 BlockTrigger：检测到高危时自动拉黑 + 添加 TTL
	det.RegisterBlockTrigger(func(ev detector.Event) bool {
		accepted, err := ipMgr.Block(ev.SourceIP)
		if err != nil {
			// 幂等跳过（IP 已在黑名单中）不视为错误
			if err == ipsetutil.ErrAlreadyBlocked {
				return false
			}
			lg.Warn("auto block failed", "ip", ev.SourceIP, "err", err)
			return false
		}
		if accepted {
			_, _ = ttlMgr.Add(ev.SourceIP, cfg.Agent.LocalBlockTTL, ttl.SourceLocal)
			lg.Info("auto blocked by detector",
				"ip", ev.SourceIP,
				"score", ev.LocalRiskScore,
				"src", ev.Source,
				"path", ev.Path,
			)
		}
		return accepted
	})

	// 5.3 初始化端口扫描检测器（portscan.enabled=true 时启用，默认关闭）
	psDet, _ := portscan.NewPortScanDetector(
		portscanCfgFromConfig(cfg.PortScan),
		func(ip string, score int) {
			accepted, err := ipMgr.Block(ip)
			if err != nil {
				if err == ipsetutil.ErrAlreadyBlocked {
					return
				}
				lg.Warn("portscan block failed", "ip", ip, "err", err)
				return
			}
			if accepted {
				_, _ = ttlMgr.Add(ip, cfg.PortScan.BlockTTL, ttl.SourceLocal)
				lg.Info("auto blocked by portscan", "ip", ip, "score", score)
			}
		},
	)
	defer psDet.Close()

	// 6. 初始化日志解析器 Registry
	parseRegistry := logparser.NewRegistry()

	// 注册用户自定义日志格式解析器（基于 config 配置）
	for name, src := range cfg.LogSources {
		if src.HasCustomRegex() {
			if err := parseRegistry.RegisterCustom(name, src.CustomRegex, src.RegexGroups); err != nil {
				lg.Warn("register custom parser failed", "name", name, "err", err)
			} else {
				lg.Info("custom parser registered", "name", name, "regex", src.CustomRegex)
			}
		}
	}
	lg.Info("log parsers registered", "names", parseRegistry.Names())

	// 6.1 预扫描历史日志建立初始基线（消除 5 分钟冷启动期）
	type preloadResult struct {
		name  string
		stats detector.PreloadStats
	}
	var preloadResults []preloadResult

	for name, src := range cfg.LogSources {
		if src.Path == "" {
			continue
		}
		p, ok := parseRegistry.Get(src.Parser)
		if !ok {
			lg.Warn("preload skipped (parser not found)", "source", name, "parser", src.Parser)
			continue
		}
		lp := func(line string) (detector.Event, error) {
			lep, err := p.Parse(line)
			if err != nil {
				return detector.Event{}, err
			}
			dev := detector.Event{
				SourceIP:       lep.SourceIP,
				Source:         lep.Source,
				Method:         lep.Method,
				Path:           lep.Path,
				Status:         lep.Status,
				BytesSent:      lep.BytesSent,
				UserAgent:      lep.UserAgent,
				Referer:        lep.Referer,
				AuthAction:     lep.AuthAction,
				RawLine:        lep.RawLine,
				Timestamp:      lep.Timestamp.Unix(),
				Body:           lep.Body,
				ContentType:    lep.ContentType,
				FileName:       lep.FileName,
				FileExt:        lep.FileExt,
				FileMime:       lep.FileMime,
				EdgeIP:         lep.EdgeIP,
				ClientIPFrom:   lep.ClientIPFrom,
				LocalRiskScore: 0,
			}
			return dev, nil
		}
		lg.Info("preloading baseline from log", "source", name, "path", src.Path, "parser", src.Parser)
		stats, err := det.PreloadFromLogFile(src.Path, detector.LineParser(lp), 10)
		if err != nil {
			lg.Warn("preload failed, continuing with cold start", "source", name, "err", err)
		} else {
			lg.Info("preload completed",
				"source", name,
				"scanned_lines", stats.ScannedLines,
				"time_range", fmt.Sprintf("%s~%s", stats.TimeStart, stats.TimeEnd),
				"duration_min", stats.DurationMin,
				"window", fmt.Sprintf("initial=10min, actual=%dmin (adaptive)", stats.ActualWindowMin),
				"buckets", fmt.Sprintf("%d total, %d healthy (>= %.0f req/5min, median=%.0f)",
					stats.TotalBuckets, stats.HealthyBuckets, stats.HealthyReqMin, stats.MedianReq),
				"qps_dist", fmt.Sprintf("P50=%.2f P95=%.2f P99=%.2f n=%d", stats.QPSP50, stats.QPSP95, stats.QPSP99, stats.QPSSamples),
				"qps_outliers_removed", stats.QPSOutliersRemoved,
				// v0.9: rate 维度基线值 — trimExtremes + MAD 双重剔除后，便于验证基线是否合理
				// 正常业务的合理范围：rate4xx/rate404 通常 < 0.10，rateAuthFail < 0.02
				"rate_p95", fmt.Sprintf("4xx=%.4f 404=%.4f 5xx=%.4f authFail=%.4f",
					stats.Rate4xxP95, stats.Rate404P95, stats.Rate5xxP95, stats.RateAuthFailP95),
				"confidence", fmt.Sprintf("%.2f", stats.Confidence),
				"baseline_qps_p95", fmt.Sprintf("win10s=%.2f win30s=%.2f win60s=%.2f", stats.BaselineQPS[0], stats.BaselineQPS[1], stats.BaselineQPS[2]),
				// IP 多样性指标（反代检测参考）
				"unique_ips", stats.UniqueIPs,
				"top1", fmt.Sprintf("%s (%d, %.1f%%)", stats.Top1IP, stats.Top1Count, stats.Top1Ratio*100),
				"top3_ratio", fmt.Sprintf("%.1f%%", stats.Top3Ratio*100),
				"elapsed", stats.Duration,
			)
			if stats.QPSOutliersRemoved > 0 {
				lg.Warn("preload removed extreme QPS buckets via MAD (likely scanner/batch/sync traffic)",
					"removed", stats.QPSOutliersRemoved)
			}
			// v0.9: 基线健康度检查 — 识别 Preload 是否被攻击流量污染
			if stats.BaselineSuspicious {
				lg.Warn("preload baseline appears contaminated (rate dimensions exceed normal range)",
					"reasons", fmt.Sprintf("%v", stats.SuspiciousReasons),
					"confidence", fmt.Sprintf("%.2f (reduced)", stats.Confidence),
					"hint", "runtime Update with G1 hard-threshold filter will overwrite this baseline within a few minutes")
			}
			preloadResults = append(preloadResults, preloadResult{name: name, stats: stats})
		}
	}

	// 6.2 反代不透传检测：所有 source preload 完后做最终判定
	for _, pr := range preloadResults {
		if pr.stats.ReverseProxyDetected {
			lg.Error("ABORTING: reverse proxy without real IP passthrough detected",
				"source", pr.name,
				"unique_ips", pr.stats.UniqueIPs,
				"top1_ip", pr.stats.Top1IP,
				"top1_count", pr.stats.Top1Count,
				"top1_ratio", fmt.Sprintf("%.1f%%", pr.stats.Top1Ratio*100),
				"top3_ratio", fmt.Sprintf("%.1f%%", pr.stats.Top3Ratio*100),
				"reason", "all requests from too few distinct IPs — real client IPs are hidden behind a proxy",
				"hint", "nginx fix: add to http {} block or inside server {}:",
				"hint_cmd", "  set_real_ip_from 10.0.0.0/8;        # upstream proxy subnet",
				"hint_cmd2", "  real_ip_header X-Forwarded-For;       # header containing real IPs",
				"hint_cmd3", "  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
			)
			os.Exit(1)
		}
	}

	// 7. 初始化 CLI 命令注册表
	cliReg := cli.NewRegistry()
	ipCliAd := &ipsetCLIAdapter{m: ipMgr}
	ttlCliAd := &ttlCLIAdapter{m: ttlMgr}

	blocklistHandler := cli.NewBlocklistHandler(ipCliAd, ttlCliAd, nil)
	blocklistHandler.Register(cliReg)

	// 注入 StatusInfo 适配器（聚合 ipMgr / ttlMgr / stats / uptime）
	statusAd := newStatusInfoAdapter(startTime, ipMgr, ttlMgr, statsCollector, cfg.Detector)
	statusHandler := cli.NewStatusHandler(statusAd, Version)
	statusHandler.Register(cliReg)

	lg.Info("cli commands registered", "commands", cliReg.Registered())

	// 8. 初始化 UnixSocket 服务端
	sockPath := cfg.UnixSocket.Path
	usReg := unixsocket.NewRegistry()

	// 桥接 cli.Registry → unixsocket.Registry
	for _, cmdName := range cliReg.Registered() {
		captureName := cmdName
		usReg.Register(captureName, func(req unixsocket.Request) unixsocket.Response {
			resp := cliReg.Dispatch(cli.Request{Command: req.Command, Args: req.Args})
			return unixsocket.Response{
				Ok:      resp.Ok,
				Error:   resp.Error,
				Data:    resp.Data,
				Message: resp.Message,
			}
		})
	}

	sockServer := unixsocket.NewServer(sockPath, usReg)
	if err := sockServer.Start(); err != nil {
		lg.Warn("unix socket start failed", "path", sockPath, "err", err)
	} else {
		lg.Info("unix socket server started", "path", sockPath)
		defer sockServer.Stop()
	}

	// 9. 初始化快照管理器
	stateDir := filepath.Dir(*configPath)
	if stateDir == "." || stateDir == "" {
		stateDir = "/var/lib/wardennet"
	}
	snapPath := filepath.Join(stateDir, "state.json")
	ipSnapAd := &ipsetAdapter{m: ipMgr}
	ttlSnapAd := &ttlAdapter{m: ttlMgr}
	snapMgr := snapshot.NewManager(
		snapshot.Config{FilePath: snapPath, Interval: 60 * time.Second},
		ipSnapAd,
		ttlSnapAd,
		nil,
	)

	// 10. 尝试从快照恢复（忽略文件不存在的首次启动场景）
	if snap, err := snapMgr.LoadAndRestore(); err != nil {
		lg.Info("snapshot restore skipped (may be first start)", "err", err)
	} else if snap != nil {
		lg.Info("snapshot restored",
			"version", snap.Version,
			"ttl_entries", len(snap.TTL.Entries),
		)
	}

	// 11. 初始化插件加载
	// - -tags=plugin 构建: CloudPlugin 编译进主程序, 直接返回 (isIntegratedCloudPlugin=true)
	// - 默认构建:         通过 plugin.Open(.so) 动态加载, 失败降级 NoopPlugin
	pluginPath := cfg.Cloud.PluginPath
	pInstance, loadErr := newCloudPlugin(pluginPath)
	if _, ok := pInstance.(*plugin.NoopPlugin); ok {
		if loadErr != nil {
			lg.Warn("plugin not loaded (will run offline)",
				"reason", loadErr.Error(),
				"path", pluginPath,
				"hint", "检查 libcloudplugin.so 是否存在、是否与主程序同 Go 版本编译")
		} else {
			lg.Info("plugin not loaded, running in offline mode")
		}
	} else {
		if isIntegratedCloudPlugin {
			lg.Info("cloud plugin loaded (integrated build)", "cloud_enabled", cfg.Cloud.Enabled)
		} else {
			lg.Info("cloud plugin loaded", "path", pluginPath)
		}
	}

	// 11.1 初始化 CloudSync 云端同步调度器（Auth → Heartbeat → Diff → Command）
	// 无插件或 cloud.enabled=false 时引擎自动跳过，零开销
	syncEngine := cloudsync.New(pInstance, ipMgr, cfg.Cloud, lg)

	// v1.2 新增：注入本地评分回调——让 DecideAll 使用 Detector 的真实评分，
	// 而不是全用 50 的中性占位值。
	syncEngine.SetLocalScoreFn(func(ip string) cloudsync.LocalScoreResult {
		if det.HasSeenRecently(ip, 60*time.Second) {
			freq, detect := det.GetLocalScores(ip)
			return cloudsync.LocalScoreResult{Freq: freq, Detector: detect}
		}
		return cloudsync.LocalScoreResult{Freq: 50, Detector: 50} // 本地未发表意见，云端分数说了算
	})

	// v1.2 新增：注入 TTL 管理器——为云端下发的 BLOCK 注册 SourceCloud 自动解封。
	// 关键安全：联防快速通道 Block 的 IP 必须能自动解封（云端评分过期/误报消除后），
	// 否则等于把"云端永远不能独立 BLOCK"的安全边界打穿成"云端下发即永久封锁"。
	syncEngine.SetTTLManager(ttlMgr)

	if err := syncEngine.Start(); err != nil {
		lg.Warn("cloud sync engine start failed (will run offline)", "err", err)
	}
	defer syncEngine.Stop()

	// 11.2 初始化 threatreporter（威胁事件 → 云端上报）
	// 无 plugin 时自动降级为静默丢弃，绝不阻塞 detector
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	agentID := fmt.Sprintf("agent-%s-%d", hostname, os.Getpid())
	reporter := threatreporter.New(pInstance, agentID, threatreporter.DefaultConfig())
	reporter.Start()
	defer reporter.Stop()

	// 注册 ThreatReportTrigger：score > 0 的威胁事件批量上报云端
	det.RegisterThreatReportTrigger(func(ev detector.Event) {
		reporter.Add(ev)
	})
	lg.Info("threat reporter initialized", "agent_id", agentID)

	// 12. 启动配置热重载
	stopWatch := loader.Watch(5*time.Second,
		// onError: reload 失败时记录日志（旧配置继续生效）
		func(err error) {
			lg.Warn("config reload failed", "err", err)
		},
		// onReloaded: reload 成功后同步运行时组件
		func(newCfg config.AgentConfig) {
			// 日志级别热切换
			if err := lg.SetLevel(newCfg.Log.Level); err != nil {
				lg.Warn("config reload: invalid log level, keeping current",
					"new_level", newCfg.Log.Level, "err", err)
			} else {
				lg.Info("config reloaded",
					"log_level", lg.CurrentLevel(),
					"ipset_whitelist", len(newCfg.IPSet.Whitelist),
					"ipset_blacklist", len(newCfg.IPSet.Blacklist),
				)
			}
		},
	)
	defer stopWatch()
	lg.Info("config watcher started", "interval", "5s")

	// 13. 启动日志 tail 消费 goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventCh := make(chan logparser.Event, 1024)
	var tailCount int
	var tails []*logparser.Tail
	for name, src := range cfg.LogSources {
		if src.Path == "" {
			lg.Info("log source has no path, skipping", "name", name)
			continue
		}
		p, ok := parseRegistry.Get(src.Parser)
		if !ok {
			lg.Warn("unknown parser, skipping", "parser", src.Parser, "source", name)
			continue
		}
		statePath := filepath.Join(stateDir, fmt.Sprintf("tail_%s_state.json", name))
		t := logparser.NewTail(src.Path, statePath, p, 1*time.Second)
		t.SetLogFn(func(level, format string, args ...interface{}) {
			switch level {
			case "debug":
				lg.Debug(fmt.Sprintf(format, args...))
			case "info":
				lg.Info(fmt.Sprintf(format, args...))
			case "warn":
				lg.Warn(fmt.Sprintf(format, args...))
			case "error":
				lg.Error(fmt.Sprintf(format, args...))
			default:
				lg.Info(fmt.Sprintf(format, args...))
			}
		})
		tails = append(tails, t)
		tailCount++
		sourceName := name // 闭包变量
		go func() {
			defer func() {
				if r := recover(); r != nil {
					lg.Error("tail goroutine panicked, restart",
						"source", sourceName, "panic", fmt.Sprintf("%v", r))
				}
			}()
			if err := t.Run(ctx, eventCh); err != nil {
				if ctx.Err() == nil {
					lg.Error("tail goroutine exited unexpectedly",
						"source", sourceName, "err", err)
				}
			}
		}()
		lg.Info("log tail started", "source", name, "path", src.Path, "parser", src.Parser)
	}

	// 14. 启动事件处理循环（消费 logparser.Event → 转换 → detector.Process）
	go func() {
		for ev := range eventCh {
			dev := convertLogEvent(ev)
			det.Process(dev)
		}
	}()

	lg.Info("agent fully initialized, waiting for events",
		"tail_sources", tailCount,
		"snapshot", snapPath,
		"detector_enabled", detCfg.Enabled,
	)

	// 15. 启动定期统计报告 goroutine（间隔由配置决定，0 表示禁用）
	reportInterval := cfg.Stats.ReportInterval
	if reportInterval > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(reportInterval) * time.Second)
			defer ticker.Stop()
			lg.Info("stats report enabled", "interval_seconds", reportInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					report := statsCollector.GenerateReport()
					// 汇总 tail 丢弃数
					var totalDropped int64
					for _, t := range tails {
						totalDropped += t.DroppedCount()
					}
					lg.Info("stats report",
						"window", report.WindowSec,
						"processed_events", report.ProcessedEvents,
						"total_events", report.TotalEvents,
						"total_ips", report.TotalIPs,
						"high_score", report.HighScoreCount,
						"medium", report.MediumCount,
						"low_score", report.LowScoreCount,
						"status_2xx", report.Status2xx,
						"status_4xx", report.Status4xx,
						"status_5xx", report.Status5xx,
						"sensitive_path", report.SensitivePathHits,
						"bot_ua", report.BotUAHits,
						"empty_referer", report.EmptyRefererHits,
						"tail_dropped", totalDropped,
					)
					// 输出 Top 5 被拉黑 IP
					if len(report.TopBlocked) > 0 {
						for i, ip := range report.TopBlocked {
							if i >= 5 {
								break
							}
							lg.Info("top blocked ip",
								"rank", i+1,
								"ip", ip.IP,
								"score", ip.Score,
								"count", ip.BlockCount,
								"sources", ip.Sources,
							)
						}
					}
					// 重置窗口
					statsCollector.Reset()
				}
			}
		}()
	} else {
		lg.Info("stats report disabled (report_interval=0)")
	}

	// 16. 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	lg.Info("received signal, shutting down", "signal", sig.String())

	// 输出最终统计报告
	finalReport := statsCollector.GenerateReport()
	lg.Info("final stats report",
		"processed_events", finalReport.ProcessedEvents,
		"total_events", finalReport.TotalEvents,
		"total_ips", finalReport.TotalIPs,
		"high_score", finalReport.HighScoreCount,
		"medium", finalReport.MediumCount,
		"low_score", finalReport.LowScoreCount,
	)

	// 优雅关闭：保存快照 + 清理 iptables 规则
	if err := snapMgr.Save(); err != nil {
		lg.Warn("snapshot save on shutdown failed", "err", err)
	} else {
		lg.Info("final snapshot saved", "path", snapPath)
	}

	// Linux 平台清理 iptables 规则（可选，保留则热重启时无需重新配置）
	platformShutdown(lg)

	cancel()
	lg.Info("agent stopped")
}

// detDetailLogger 实现 detector.DetailLogger，将评分详情记录到日志和统计收集器。
type detDetailLogger struct {
	lg       *logger.Logger
	stats    *stats.Collector
	scoreLow int // score_low 阈值：低于此分数的事件不进统计也不打 debug
}

// LogDetail 记录单个事件的评分详情。
// 仅当 finalScore >= scoreLow 时才写入统计收集器和 debug 日志，避免正常流量刷屏。
func (d *detDetailLogger) LogDetail(ev detector.Event, details [3]detector.ScoreDetail, finalScore int, isHigh bool, blocked bool) {
	// 先记录 processed_events（全量，不受 score_low 过滤）
	d.stats.IncrementProcessed()

	// 低于 score_low 阈值：跳过统计和 debug 日志
	threshold := d.scoreLow
	if threshold <= 0 {
		threshold = 10 // 兜底：没配置时默认 10
	}
	if finalScore < threshold {
		return
	}

	// 记录到统计收集器
	d.stats.Record(stats.EventRecord{
		Timestamp: ev.Timestamp,
		SourceIP:  ev.SourceIP,
		Score:     finalScore,
		IsHigh:    isHigh,
		Source:    ev.Source,
		Path:      ev.Path,
		Method:    ev.Method,
		UserAgent: ev.UserAgent,
		Status:    ev.Status,
		Dimensions: map[string]interface{}{
			"sensitive_path":   details[2].SensitivePathScore > 0 || details[1].SensitivePathScore > 0 || details[0].SensitivePathScore > 0,
			"bot_ua":           details[2].BotUAScore > 0 || details[1].BotUAScore > 0 || details[0].BotUAScore > 0,
			"empty_referer":    details[2].EmptyRefererScore > 0 || details[1].EmptyRefererScore > 0 || details[0].EmptyRefererScore > 0,
			"dangerous_method": details[2].DangerousMethodScore > 0 || details[1].DangerousMethodScore > 0 || details[0].DangerousMethodScore > 0,
			"auth_fail":        details[2].AuthFailScore > 0 || details[1].AuthFailScore > 0 || details[0].AuthFailScore > 0,
		},
	})

	// Debug 级别记录详情（仅 debug 日志模式下可见；低于 score_low 的已提前 return）
	d.lg.Debug("detector score detail",
		"ip", ev.SourceIP,
		"score", finalScore,
		"is_high", isHigh,
		"blocked", blocked,
		"source", ev.Source,
		"path", ev.Path,
		"method", ev.Method,
		"status", ev.Status,
		"ua", truncateStr(ev.UserAgent, 60),
		"win10s", detector.ScoreDetailString(details[0]),
		"win30s", detector.ScoreDetailString(details[1]),
		"win60s", detector.ScoreDetailString(details[2]),
	)

	// WARN 分级：只在确认要封禁时才打 WARN
	// blocked=false 的 isHigh（进入观察名单）仅打 Debug，避免一过性高分刷屏
	if isHigh && blocked {
		d.lg.Warn("high score event detected, blocking",
			"ip", ev.SourceIP,
			"score", finalScore,
			"source", ev.Source,
			"path", ev.Path,
			"method", ev.Method,
			"status", ev.Status,
			"ua", truncateStr(ev.UserAgent, 60),
		)
	}
}

// truncateStr 截断字符串到指定长度。
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// convertLogEvent 将 logparser.Event 转换为 detector.Event。
// 两个结构字段高度重叠，此转换确保类型安全地衔接解析器与检测器。
func convertLogEvent(ev logparser.Event) detector.Event {
	return detector.Event{
		SourceIP:       ev.SourceIP,
		Source:         ev.Source,
		Method:         ev.Method,
		Path:           ev.Path,
		Status:         ev.Status,
		BytesSent:      ev.BytesSent,
		UserAgent:      ev.UserAgent,
		Referer:        ev.Referer,
		AuthAction:     ev.AuthAction,
		LocalRiskScore: 0,
		RawLine:        ev.RawLine,
		Timestamp:      ev.Timestamp.Unix(),

		// v1.0 新增字段（旧 parser 不填充时为零值，BodyScanner 自动跳过）
		Body:        ev.Body,
		ContentType: ev.ContentType,
		FileName:    ev.FileName,
		FileExt:     ev.FileExt,
		FileMime:    ev.FileMime,

		// v1.1 新增：Cloudflare/代理双 IP 识别
		EdgeIP:       ev.EdgeIP,
		ClientIPFrom: ev.ClientIPFrom,
	}
}

// portscanCfgFromConfig 将 config.PortScanCfg 转换为 portscan.PortScanConfig。
// 两个结构体字段一一对应，portscan 包零跨包依赖，所以必须在 main 层做桥接。
func portscanCfgFromConfig(c config.PortScanCfg) portscan.PortScanConfig {
	var windows [3]portscan.PortWindow
	for i := 0; i < 3; i++ {
		windows[i] = portscan.PortWindow{
			Size:     c.Windows[i].Size,
			MaxPorts: c.Windows[i].MaxPorts,
		}
	}
	return portscan.PortScanConfig{
		Enabled:    c.Enabled,
		Source:     c.Source,
		LogPath:    c.LogPath,
		LogPrefix:  c.LogPrefix,
		BlockTTL:   c.BlockTTL,
		Weight:     c.Weight,
		PcapIface:  c.PcapIface,
		PcapFilter: c.PcapFilter,
		Windows:    windows,
	}
}
