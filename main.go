package main

import (
 "bufio"
 "flag"
 "fmt"
 "io/ioutil"
 "os"
 "os/exec"
 "os/signal"
 "os/user"
 "path/filepath"
 "strconv"
 "strings"
 "syscall"
 "time"

 "github.com/digitalocean/go-libvirt"
 "github.com/digitalocean/go-libvirt/socket/dialers"
)

const (
 VIR_DOMAIN_MEMORY_STAT_UNUSED    = 4
 VIR_DOMAIN_MEMORY_STAT_AVAILABLE = 5
 VIR_DOMAIN_MEMORY_STAT_RSS       = 7
 VIR_DOMAIN_MEMORY_STAT_USABLE    = 8
)

type VMMetrics struct {
 Type          string
 ID            string
 Name          string
 State         string
 VCPUs         uint32
 MaxMemKB      uint64
 CurMemKB      uint64
 RSSKB         uint64
 GuestAvailKB  uint64
 GuestUnusedKB uint64
 GuestUsableKB uint64
 GuestUsedKB   uint64
 UtilPercent   float64
 IdleRssKB     uint64
 HostUtilPct   float64
}

type NumaNode struct {
 ID    int
 Total uint64
 Free  uint64
}

type SwapBreakdown struct {
 DiskTotalKB uint64
 DiskUsedKB  uint64
 ZramDiskKB  uint64
 ZramUsedKB  uint64
 ZramOrigKB  uint64
 ZramComprKB uint64
 ZramMemKB   uint64
 ZramDevs    int
}

type ModuleStatus struct {
 Loaded   bool
 RefCount int
}

func getPageSizeKB() uint64 {
 return uint64(os.Getpagesize()) / 1024
}

func formatSize(kb uint64) string {
 if kb == 0 {
  return "-"
 }
 val := float64(kb)
 if val >= 1024*1024*1024 {
  return fmt.Sprintf("%.2f TiB", val/(1024*1024*1024))
 }
 if val >= 1024*1024 {
  return fmt.Sprintf("%.2f GiB", val/(1024*1024))
 }
 return fmt.Sprintf("%.2f MiB", val/1024)
}

func getHostMeminfo() (map[string]uint64, error) {
 file, err := os.Open("/proc/meminfo")
 if err != nil {
  return nil, err
 }
 defer file.Close()

 meminfo := make(map[string]uint64)
 scanner := bufio.NewScanner(file)
 for scanner.Scan() {
  line := scanner.Text()
  parts := strings.Fields(line)
  if len(parts) >= 2 {
   key := strings.TrimSuffix(parts[0], ":")
   val, err := strconv.ParseUint(parts[1], 10, 64)
   if err == nil {
    meminfo[key] = val
   }
  }
 }
 return meminfo, nil
}

func getNumaNodes() ([]NumaNode, error) {
 var nodes []NumaNode
 matches, err := filepath.Glob("/sys/devices/system/node/node[0-9]*")
 if err != nil || len(matches) == 0 {
  return nil, err
 }

 for _, path := range matches {
  nodeStr := filepath.Base(path)
  id, err := strconv.Atoi(strings.TrimPrefix(nodeStr, "node"))
  if err != nil {
   continue
  }

  node := NumaNode{ID: id}
  meminfoBytes, err := ioutil.ReadFile(filepath.Join(path, "meminfo"))
  if err == nil {
   scanner := bufio.NewScanner(strings.NewReader(string(meminfoBytes)))
   for scanner.Scan() {
    fields := strings.Fields(scanner.Text())
    if len(fields) >= 4 {
     val, _ := strconv.ParseUint(fields[3], 10, 64)
     if strings.Contains(fields[2], "MemTotal") {
      node.Total = val
     } else if strings.Contains(fields[2], "MemFree") {
      node.Free = val
     }
    }
   }
  }
  nodes = append(nodes, node)
 }
 return nodes, nil
}

func getKernelModulesStatus() map[string]ModuleStatus {
 status := map[string]ModuleStatus{
  "kvm":       {Loaded: false, RefCount: 0},
  "kvm_intel": {Loaded: false, RefCount: 0},
  "kvm_amd":   {Loaded: false, RefCount: 0},
  "vboxdrv":   {Loaded: false, RefCount: 0},
 }
 file, err := os.Open("/proc/modules")
 if err != nil {
  return status
 }
 defer file.Close()

 scanner := bufio.NewScanner(file)
 for scanner.Scan() {
  fields := strings.Fields(scanner.Text())
  if len(fields) >= 3 {
   modName := fields[0]
   if _, exists := status[modName]; exists {
    refCount, _ := strconv.Atoi(fields[2])
    status[modName] = ModuleStatus{Loaded: true, RefCount: refCount}
   }
  }
 }
 return status
}

func getProcessRSSKB(pid int) uint64 {
 data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
 if err != nil {
  return 0
 }
 fields := strings.Fields(string(data))
 if len(fields) >= 2 {
  pages, _ := strconv.ParseUint(fields[1], 10, 64)
  return pages * getPageSizeKB()
 }
 return 0
}

func getKvmDomainType(l *libvirt.Libvirt, d libvirt.Domain, pid int) string {
 xmlDesc, err := l.DomainGetXMLDesc(d, 0)
 if err == nil {
  if strings.Contains(xmlDesc, "<domain type='kvm'") {
   return "KVM(HW)"
  }
  if strings.Contains(xmlDesc, "<domain type='qemu'") {
   return "KVM(TCG)"
  }
 }

 if pid > 0 {
  cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
  if err == nil {
   cmd := strings.ReplaceAll(string(cmdBytes), "\x00", " ")
   if strings.Contains(cmd, "-accel tcg") {
    return "KVM(TCG)"
   }
   if strings.Contains(cmd, "-enable-kvm") || strings.Contains(cmd, "-accel kvm") {
    return "KVM(HW)"
   }
  }
 }

 return "KVM"
}

func findQemuPID(vmName string) int {
 matches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
 for _, p := range matches {
  cmdBytes, err := os.ReadFile(p)
  if err != nil {
   continue
  }
  cmdClean := strings.ReplaceAll(string(cmdBytes), "\x00", " ")
  if strings.Contains(cmdClean, "qemu-system") && strings.Contains(cmdClean, vmName) {
   dir := filepath.Dir(p)
   pidStr := filepath.Base(dir)
   pid, err := strconv.Atoi(pidStr)
   if err == nil {
    return pid
   }
  }
 }
 return 0
}

func getVBoxManageCmd() string {
 if p, err := exec.LookPath("VBoxManage"); err == nil {
  return p
 }
 if p, err := exec.LookPath("vboxmanage"); err == nil {
  return p
 }
 return "VBoxManage"
}

func parseVBoxCmdline(cmd string) (name string, uuid string) {
 args := strings.Split(cmd, "\x00")
 if len(args) <= 1 {
  args = strings.Fields(cmd)
 }

 for i := 0; i < len(args); i++ {
  arg := args[i]
  if (arg == "--comment" || arg == "-comment") && i+1 < len(args) {
   name = args[i+1]
  }
  if (arg == "--startvm" || arg == "-startvm") && i+1 < len(args) {
   val := args[i+1]
   if name == "" {
    name = val
   } else {
    uuid = val
   }
  }
 }
 return
}

func getProcessOwner(pid int) (uid uint32, gid uint32, username string) {
 fi, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
 if err != nil {
  return 0, 0, ""
 }
 stat, ok := fi.Sys().(*syscall.Stat_t)
 if !ok {
  return 0, 0, ""
 }
 uid = stat.Uid
 gid = stat.Gid

 u, err := user.LookupId(strconv.Itoa(int(uid)))
 if err == nil {
  username = u.Username
 }
 return
}

func runVBoxCmdAsUser(vboxCmd string, username string, uid uint32, gid uint32, args ...string) ([]byte, error) {
 cmd := exec.Command(vboxCmd, args...)
 if os.Geteuid() == 0 && uid != 0 {
  cmd.SysProcAttr = &syscall.SysProcAttr{
   Credential: &syscall.Credential{Uid: uid, Gid: gid},
  }

  u, err := user.LookupId(strconv.Itoa(int(uid)))
  if err == nil {
   var cleanEnv []string
   for _, env := range os.Environ() {
    if !strings.HasPrefix(env, "HOME=") && !strings.HasPrefix(env, "USER=") && !strings.HasPrefix(env, "LOGNAME=") {
     cleanEnv = append(cleanEnv, env)
    }
   }
   cmd.Env = append(cleanEnv,
    "HOME="+u.HomeDir,
    "USER="+username,
    "LOGNAME="+username,
   )
  }
 }
 return cmd.Output()
}

func getVBoxVMs(modules map[string]ModuleStatus) []VMMetrics {
 var vms []VMMetrics
 vboxCmd := getVBoxManageCmd()
 foundVMs := make(map[string]bool)

 procMatches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
 for _, p := range procMatches {
  cmdBytes, err := os.ReadFile(p)
  if err != nil {
   continue
  }
  cmdClean := string(cmdBytes)
  if strings.Contains(cmdClean, "VirtualBoxVM") || strings.Contains(cmdClean, "VBoxHeadless") {
   vmName, vmUUID := parseVBoxCmdline(cmdClean)
   if vmName == "" && vmUUID == "" {
    continue
   }

   dir := filepath.Dir(p)
   pidStr := filepath.Base(dir)
   pid, _ := strconv.Atoi(pidStr)
   if foundVMs[pidStr] {
    continue
   }
   foundVMs[pidStr] = true

   uid, gid, username := getProcessOwner(pid)
   rssKB := getProcessRSSKB(pid)

   displayName := vmName
   if displayName == "" {
    displayName = vmUUID
   }

   targetVM := vmUUID
   if targetVM == "" {
    targetVM = displayName
   }

   var memoryMB uint64 = 0
   var cpus uint32 = 2

   infoOut, err := runVBoxCmdAsUser(vboxCmd, username, uid, gid, "showvminfo", targetVM, "--machinereadable")
   if err == nil {
    scanner := bufio.NewScanner(strings.NewReader(string(infoOut)))
    for scanner.Scan() {
     prop := scanner.Text()
     if strings.HasPrefix(prop, "memory=") {
      val, _ := strconv.ParseUint(strings.TrimPrefix(prop, "memory="), 10, 64)
      memoryMB = val
     } else if strings.HasPrefix(prop, "cpus=") {
      val, _ := strconv.ParseUint(strings.TrimPrefix(prop, "cpus="), 10, 32)
      cpus = uint32(val)
     }
    }
   }

   memKB := memoryMB * 1024
   if memKB == 0 {
    memKB = rssKB
   }

   vmType := "VBOX(HW)"
   if !modules["vboxdrv"].Loaded {
    vmType = "VBOX(TCG)"
   }

   vm := VMMetrics{
    Type:     vmType,
    ID:       pidStr,
    Name:     displayName,
    State:    "R",
    VCPUs:    cpus,
    MaxMemKB: memKB,
    CurMemKB: memKB,
    RSSKB:    rssKB,
   }

   mOut, mErr := runVBoxCmdAsUser(vboxCmd, username, uid, gid, "metrics", "query", targetVM, "Guest/RAM/Usage/Total,Guest/RAM/Usage/Free")
   if mErr != nil || len(mOut) == 0 || strings.Contains(string(mOut), "No collected metric data") || !strings.Contains(string(mOut), "Guest/RAM/Usage") {
    _, _ = runVBoxCmdAsUser(vboxCmd, username, uid, gid, "metrics", "setup", "--period", "1", "--samples", "1", targetVM)
    time.Sleep(1200 * time.Millisecond)
    mOut, mErr = runVBoxCmdAsUser(vboxCmd, username, uid, gid, "metrics", "query", targetVM, "Guest/RAM/Usage/Total,Guest/RAM/Usage/Free")
   }

   if mErr == nil {
    scanner := bufio.NewScanner(strings.NewReader(string(mOut)))
    for scanner.Scan() {
     line := scanner.Text()
     if strings.Contains(line, "Guest/RAM/Usage/Total") {
      fields := strings.Fields(line)
      if len(fields) >= 3 {
       valStr := fields[len(fields)-2]
       if val, err := strconv.ParseUint(valStr, 10, 64); err == nil {
        vm.GuestAvailKB = val
       }
      }
     } else if strings.Contains(line, "Guest/RAM/Usage/Free") {
      fields := strings.Fields(line)
      if len(fields) >= 3 {
       valStr := fields[len(fields)-2]
       if val, err := strconv.ParseUint(valStr, 10, 64); err == nil {
        vm.GuestUsableKB = val
        vm.GuestUnusedKB = val
       }
      }
     }
    }
   }

   if vm.GuestAvailKB > 0 {
    if vm.GuestAvailKB >= vm.GuestUsableKB {
     vm.GuestUsedKB = vm.GuestAvailKB - vm.GuestUsableKB
    }
    vm.UtilPercent = float64(vm.GuestUsedKB) / float64(vm.GuestAvailKB) * 100
   }

   gFreeVal := vm.GuestUsableKB
   if gFreeVal == 0 {
    gFreeVal = vm.GuestUnusedKB
   }
   idleInRss := vm.RSSKB
   if gFreeVal < idleInRss {
    idleInRss = gFreeVal
   }
   vm.IdleRssKB = idleInRss

   if vm.CurMemKB > 0 {
    vm.HostUtilPct = float64(vm.RSSKB) / float64(vm.CurMemKB) * 100
   }

   vms = append(vms, vm)
  }
 }

 return vms
}

func getDetailedSwap() (SwapBreakdown, error) {
 var sb SwapBreakdown
 file, err := os.Open("/proc/swaps")
 if err != nil {
  return sb, err
 }
 defer file.Close()

 scanner := bufio.NewScanner(file)
 if scanner.Scan() {
  _ = scanner.Text()
 }

 for scanner.Scan() {
  fields := strings.Fields(scanner.Text())
  if len(fields) < 4 {
   continue
  }
  name := fields[0]
  sizeKB, _ := strconv.ParseUint(fields[2], 10, 64)
  usedKB, _ := strconv.ParseUint(fields[3], 10, 64)

  if strings.HasPrefix(name, "/dev/zram") {
   sb.ZramDiskKB += sizeKB
   sb.ZramUsedKB += usedKB
   sb.ZramDevs++
  } else {
   sb.DiskTotalKB += sizeKB
   sb.DiskUsedKB += usedKB
  }
 }

 matches, _ := filepath.Glob("/sys/block/zram*/mm_stat")
 for _, p := range matches {
  data, err := ioutil.ReadFile(p)
  if err == nil {
   parts := strings.Fields(string(data))
   if len(parts) >= 3 {
    origBytes, _ := strconv.ParseUint(parts[0], 10, 64)
    comprBytes, _ := strconv.ParseUint(parts[1], 10, 64)
    memBytes, _ := strconv.ParseUint(parts[2], 10, 64)

    sb.ZramOrigKB += origBytes / 1024
    sb.ZramComprKB += comprBytes / 1024
    sb.ZramMemKB += memBytes / 1024
   }
  }
 }

 if sb.ZramOrigKB == 0 && sb.ZramUsedKB > 0 {
  sb.ZramOrigKB = sb.ZramUsedKB
 }

 return sb, nil
}

func getKsmInfo() (sharingKiB uint64, runStatus string) {
 runBytes, err := ioutil.ReadFile("/sys/kernel/mm/ksm/run")
 if err == nil {
  switch strings.TrimSpace(string(runBytes)) {
  case "1":
   runStatus = "Active"
  default:
   runStatus = "Inactive"
  }
 } else {
  runStatus = "N/A"
 }

 sharingBytes, err := ioutil.ReadFile("/sys/kernel/mm/ksm/pages_sharing")
 if err == nil {
  pages, _ := strconv.ParseUint(strings.TrimSpace(string(sharingBytes)), 10, 64)
  sharingKiB = pages * 4
 }
 return
}

func stateToString(state uint8) string {
 switch state {
 case 1:
  return "R"
 case 2:
  return "B"
 case 3:
  return "P"
 case 4:
  return "S"
 case 5:
  return "O"
 case 6:
  return "C"
 case 7:
  return "M"
 default:
  return "?"
 }
}

func render(l *libvirt.Libvirt, libvirtConnected bool, version string, clearScreen bool) {
 meminfo, err := getHostMeminfo()
 if err != nil {
  fmt.Printf("Ошибка получения данных о памяти хоста: %v\n", err)
  return
 }

 total := meminfo["MemTotal"]
 free := meminfo["MemFree"]
 buffers := meminfo["Buffers"]
 cached := meminfo["Cached"]
 shared := meminfo["Shmem"]
 available := meminfo["MemAvailable"]
 used := total - free - buffers - cached

 zswap := meminfo["Zswap"]
 zswapped := meminfo["Zswapped"]

 ksmSharing, ksmStatus := getKsmInfo()
 sw, _ := getDetailedSwap()

 diskFreeKB := uint64(0)
 if sw.DiskTotalKB > sw.DiskUsedKB {
  diskFreeKB = sw.DiskTotalKB - sw.DiskUsedKB
 }

 zramRatio := 0.0
 if sw.ZramMemKB > 0 && sw.ZramOrigKB > 0 {
  zramRatio = float64(sw.ZramOrigKB) / float64(sw.ZramMemKB)
 }

 if clearScreen {
  fmt.Print("\033[H\033[2J")
 }

 now := time.Now().Format("15:04:05")
 fmt.Printf("=== VIRT-TOP-GO (libvirt ver: %s) | Time: %s ===\n", version, now)
 fmt.Printf("Host Memory   : TOTAL: %-10s | FREE: %-10s | USED: %-10s | AVAIL: %s\n",
  formatSize(total), formatSize(free), formatSize(used), formatSize(available))
 fmt.Printf("Cache/Buffers : CACHED: %-9s | BUFFERS: %-7s | SHARED: %s\n",
  formatSize(cached), formatSize(buffers), formatSize(shared))

 fmt.Printf("Disk Swap     : TOTAL: %-10s | USED: %-10s | FREE: %s\n",
  formatSize(sw.DiskTotalKB), formatSize(sw.DiskUsedKB), formatSize(diskFreeKB))

 if sw.ZramDevs > 0 {
  fmt.Printf("ZRAM (In-RAM) : DATA: %-11s | REAL RAM: %-6s | RATIO: %.2fx (Devs: %d, DiskPool: %s)\n",
   formatSize(sw.ZramOrigKB), formatSize(sw.ZramMemKB), zramRatio, sw.ZramDevs, formatSize(sw.ZramDiskKB))
 } else {
  fmt.Printf("ZRAM (In-RAM) : Not active\n")
 }

 fmt.Printf("Compression   : ZSWAP: %-10s | ZSWAPPED: %-6s | KSM Saved (De-dup): %s (Status: %s)\n",
  formatSize(zswap), formatSize(zswapped), formatSize(ksmSharing), ksmStatus)

 modules := getKernelModulesStatus()
 var modParts []string
 for _, m := range []string{"kvm", "kvm_intel", "kvm_amd", "vboxdrv"} {
  stat := modules[m]
  if stat.Loaded {
   modParts = append(modParts, fmt.Sprintf("%s: OK (Ref: %d)", m, stat.RefCount))
  } else {
   modParts = append(modParts, fmt.Sprintf("%s: -", m))
  }
 }
 fmt.Printf("Kernel Modules: %s\n", strings.Join(modParts, " | "))

 numaNodes, err := getNumaNodes()
 if err == nil && len(numaNodes) > 0 {
  fmt.Printf("NUMA Nodes    : ")
  for _, node := range numaNodes {
   nodeFreePct := float64(0)
   if node.Total > 0 {
    nodeFreePct = float64(node.Free) / float64(node.Total) * 100
   }
   fmt.Printf("[Node %d: Free %s/%s (%.1f%%)] ", node.ID, formatSize(node.Free), formatSize(node.Total), nodeFreePct)
  }
  fmt.Println()
 }

 var kvmVMs []VMMetrics
 if libvirtConnected {
  flags := libvirt.ConnectListDomainsActive
  domains, _, err := l.ConnectListAllDomains(1, flags)
  if err == nil {
   for _, d := range domains {
    state, maxMem, memory, nrVirtCpu, _, err := l.DomainGetInfo(d)
    if err != nil {
     continue
    }

    vmPid := findQemuPID(d.Name)
    vmType := getKvmDomainType(l, d, vmPid)

    vm := VMMetrics{
     Type:     vmType,
     ID:       strconv.Itoa(int(d.ID)),
     Name:     d.Name,
     State:    stateToString(state),
     VCPUs:    uint32(nrVirtCpu),
     MaxMemKB: maxMem,
     CurMemKB: memory,
    }

    memStats, err := l.DomainMemoryStats(d, 16, 0)
    if err == nil {
     for _, stat := range memStats {
      switch stat.Tag {
      case VIR_DOMAIN_MEMORY_STAT_RSS:
       vm.RSSKB = stat.Val
      case VIR_DOMAIN_MEMORY_STAT_AVAILABLE:
       vm.GuestAvailKB = stat.Val
      case VIR_DOMAIN_MEMORY_STAT_UNUSED:
       vm.GuestUnusedKB = stat.Val
      case VIR_DOMAIN_MEMORY_STAT_USABLE:
       vm.GuestUsableKB = stat.Val
      }
     }
    }

    if vm.RSSKB == 0 && vmPid > 0 {
     vm.RSSKB = getProcessRSSKB(vmPid)
    }

    base := vm.GuestAvailKB
    if base == 0 {
     base = vm.CurMemKB
    }
    unused := vm.GuestUsableKB
    if unused == 0 {
     unused = vm.GuestUnusedKB
    }
    if base >= unused {
     vm.GuestUsedKB = base - unused
    }
    if base > 0 {
     vm.UtilPercent = float64(vm.GuestUsedKB) / float64(base) * 100
    }

    gFreeVal := unused
    idleInRss := vm.RSSKB
    if gFreeVal > 0 && gFreeVal < idleInRss {
     idleInRss = gFreeVal
    }
    vm.IdleRssKB = idleInRss

    if vm.CurMemKB > 0 {
     vm.HostUtilPct = float64(vm.RSSKB) / float64(vm.CurMemKB) * 100
    }

    kvmVMs = append(kvmVMs, vm)
   }
  }
 }

 vboxVMs := getVBoxVMs(modules)

 var vms []VMMetrics
 vms = append(vms, kvmVMs...)
 vms = append(vms, vboxVMs...)

 var sumMaxKB, sumAllocKB, sumRSSKB, sumGAvailKB, sumGFreeKB, sumIdleRssKB uint64
 var sumKVM_RSSKB, sumVBox_RSSKB uint64
 var sumRemainingAllocKB, sumRemainingMaxKB uint64

 for _, vm := range vms {
  sumMaxKB += vm.MaxMemKB
  sumAllocKB += vm.CurMemKB
  sumRSSKB += vm.RSSKB

  if strings.HasPrefix(vm.Type, "KVM") {
   sumKVM_RSSKB += vm.RSSKB
  } else {
   sumVBox_RSSKB += vm.RSSKB
  }

  gFreeVal := vm.GuestUsableKB
  if gFreeVal == 0 {
   gFreeVal = vm.GuestUnusedKB
  }

  sumGAvailKB += vm.GuestAvailKB
  sumGFreeKB += gFreeVal
  sumIdleRssKB += vm.IdleRssKB

  if vm.CurMemKB > vm.RSSKB {
   sumRemainingAllocKB += (vm.CurMemKB - vm.RSSKB)
  }
  if vm.MaxMemKB > vm.RSSKB {
   sumRemainingMaxKB += (vm.MaxMemKB - vm.RSSKB)
  }
 }

 hostFreePct := float64(0)
 hostAvailPct := float64(0)
 hostRssPct := float64(0)
 if total > 0 {
  hostFreePct = float64(free) / float64(total) * 100
  hostAvailPct = float64(available) / float64(total) * 100
  hostRssPct = float64(sumRSSKB) / float64(total) * 100
 }

 hostPotAvailKB := available + sumIdleRssKB
 hostPotAvailPct := float64(0)
 if total > 0 {
  hostPotAvailPct = float64(hostPotAvailKB) / float64(total) * 100
 }

 headroomAllocKB := uint64(0)
 if available > sumRemainingAllocKB {
  headroomAllocKB = available - sumRemainingAllocKB
 }
 headroomAllocPct := float64(0)
 if total > 0 {
  headroomAllocPct = float64(headroomAllocKB) / float64(total) * 100
 }

 headroomMaxKB := uint64(0)
 if available > sumRemainingMaxKB {
  headroomMaxKB = available - sumRemainingMaxKB
 }
 headroomMaxPct := float64(0)
 if total > 0 {
  headroomMaxPct = float64(headroomMaxKB) / float64(total) * 100
 }

 fmt.Println("\n=== SUMMARY (All Active VMs) ===")

 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")
 fmt.Printf("%-18s %-16s %-10s %-12s %-10s %-10s %-19s %-19s %-16s %-11s %-10s\n",
  "Total", "Total", "Total Host", "Total Host", "KVM RSS", "VBox RSS", "Host Memory", "Host Memory", "Guest", "Guest", "Guest")
 fmt.Printf("%-18s %-16s %-10s %-12s %-10s %-10s %-19s %-19s %-16s %-11s %-10s\n",
  "VMs Configured MAX", "Allocated to VMs", "Memory RSS", "% Memory RSS", "", "", "Free", "Available", "available Memory", "Free Memory", "idleInRss")
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")

 valHostRssPct := fmt.Sprintf("%.2f%%", hostRssPct)
 valHostFree := fmt.Sprintf("%s (%.2f%%)", formatSize(free), hostFreePct)
 valHostAvail := fmt.Sprintf("%s (%.2f%%)", formatSize(available), hostAvailPct)

 fmt.Printf("%-18s %-16s %-10s %-12s %-10s %-10s %-19s %-19s %-16s %-11s %-10s\n",
  formatSize(sumMaxKB),
  formatSize(sumAllocKB),
  formatSize(sumRSSKB),
  valHostRssPct,
  formatSize(sumKVM_RSSKB),
  formatSize(sumVBox_RSSKB),
  valHostFree,
  valHostAvail,
  formatSize(sumGAvailKB),
  formatSize(sumGFreeKB),
  formatSize(sumIdleRssKB),
 )
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")

 fmt.Println("\n=== HOST PROJECTIONS & HEADROOM ===")
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")
 fmt.Printf("%-30s %-28s %-38s %-42s\n",
  "Host Potential Available", "Sum idle VM RSS reclaimed", "Worst-Case Headroom (Alloc) buffer", "Worst-Case Headroom (Max) buffer")
 fmt.Printf("%-30s %-28s %-38s %-42s\n",
  "+ Sum idle VM RSS reclaimed", "", "if VMs claim 100% of allocated RAM", "if VMs expanded to max configured limit")
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")

 valHostPotAvail := fmt.Sprintf("%s (%.2f%%)", formatSize(hostPotAvailKB), hostPotAvailPct)
 valReclaimed := formatSize(sumIdleRssKB)
 valHeadroomAlloc := fmt.Sprintf("%s (%.2f%%)", formatSize(headroomAllocKB), headroomAllocPct)
 valHeadroomMax := fmt.Sprintf("%s (%.2f%%)", formatSize(headroomMaxKB), headroomMaxPct)

 fmt.Printf("%-30s %-28s %-38s %-42s\n",
  valHostPotAvail, valReclaimed, valHeadroomAlloc, valHeadroomMax)
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")

 fmt.Println("\n=== ACTIVE VIRTUAL MACHINES LIST ===")
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")
 fmt.Printf("%-7s %-9s %-3s %-20s %-5s %-12s %-12s %-12s %-12s %-12s %-12s %-12s %-12s\n",
  "ID", "TYPE", "S", "NAME", "VCPU", "MAX_LIMIT", "ALLOC_ACT", "HOST_RSS", "HOST_UTIL", "GUEST_AVAIL", "GUEST_FREE", "IDLE_RSS", "GUEST_UTIL")
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")

 for _, vm := range vms {
  gFreeVal := vm.GuestUsableKB
  if gFreeVal == 0 {
   gFreeVal = vm.GuestUnusedKB
  }

  utilStr := "-"
  if vm.GuestAvailKB > 0 {
   utilStr = fmt.Sprintf("%.1f%%", vm.UtilPercent)
  }

  hostUtilStr := "-"
  if vm.CurMemKB > 0 {
   hostUtilStr = fmt.Sprintf("%.1f%%", vm.HostUtilPct)
  }

  fmt.Printf("%-7s %-9s %-3s %-20s %-5d %-12s %-12s %-12s %-12s %-12s %-12s %-12s %-12s\n",
   vm.ID, vm.Type, vm.State, vm.Name, vm.VCPUs,
   formatSize(vm.MaxMemKB), formatSize(vm.CurMemKB), formatSize(vm.RSSKB),
   hostUtilStr,
   formatSize(vm.GuestAvailKB), formatSize(gFreeVal), formatSize(vm.IdleRssKB), utilStr)
 }
 fmt.Println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------")
}

func main() {
 topOpt := flag.Bool("top", false, "Run in top-like mode (interactive, clears screen on each update)")
 streamOpt := flag.Bool("stream", false, "Run in continuous stream mode (appends to stdout, like virt-top --stream)")
 delayOpt := flag.Int("delay", 2, "Delay between updates in seconds")
 flag.Parse()

 l := libvirt.NewWithDialer(dialers.NewLocal())
 libvirtConnected := false
 var version string

 if err := l.Connect(); err == nil {
  libvirtConnected = true
  defer l.Disconnect()
  v, errVersion := l.Version()
  if errVersion == nil {
   version = v
  } else {
   version = "unknown"
  }
 } else {
  version = "Libvirt N/A"
 }

 if !*topOpt && !*streamOpt {
  render(l, libvirtConnected, version, false)
  return
 }

 clearScreen := *topOpt

 sigChan := make(chan os.Signal, 1)
 signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

 ticker := time.NewTicker(time.Duration(*delayOpt) * time.Second)
 defer ticker.Stop()

 for {
  render(l, libvirtConnected, version, clearScreen)
  select {
  case <-ticker.C:
  case <-sigChan:
   fmt.Println("\nЗавершено.")
   return
  }
 }
}
