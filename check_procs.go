package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
  "github.com/fractalcat/nagiosplugin"
)

func main() {
	nodeName, _ := os.Hostname()

	modePtr := flag.String("m", "check", "Whether to handle this request as a metric or a check. Supported values: check,metric,boolean")
	procPtr := flag.String("p", "undefined", "The process to look for")
	warnMinPtr := flag.Int("W", 0, "Warn MIN: The minimum number of expected processes. Fewer active processes will trigger a WARNING")
	warnMaxPtr := flag.Int("w", 50, "Warn MAX: The maximum number of expected processes. More running processes will trigger a WARNING")
	critMinPtr := flag.Int("C", 1, "Crit MIN:  The minimum number of expected processes. Fewer active processes will trigger a CRITICAL")
	critMaxPtr := flag.Int("c", 100, "Crit MAX: The maximum number of expected processes. More running processes will trigger a WARNING")
	schemePtr := flag.String("s", "", "the Scheme to use for the metric prefix.")
	searchPtr := flag.Bool("n", true, "Whether to match against the process name. If -n=false the commandline will be searched instead")
	regexPtr := flag.Bool("r", false, "Whether to perform a regex match against the processname or commandline (slower). The default is to perform an equality comparison")

	flag.Parse()

	if string(*procPtr) == "undefined" {
		log.Fatal("Must provide a process to check")
	}

	var scheme string

	if string(*schemePtr) == "" {
		scheme = string(nodeName + ".processcount." + string(*procPtr))
	} else {
		scheme = string(string(*schemePtr) + ".processcount." + string(*procPtr))
	}
	getPidCmd()
	//determine if we want a check, or a metric
	switch *modePtr {
	case "check", "c":
		check(*procPtr, *warnMinPtr, *warnMaxPtr, *critMinPtr, *critMaxPtr, *searchPtr, *regexPtr)
	case "metric", "m":
		metric(*procPtr, scheme, *searchPtr, *regexPtr)
	case "boolean", "b":
	  boolproc(*procPtr, *searchPtr, *regexPtr)
	default:
		log.Fatal("Must pass either 'check' or 'metric' to the mode flag. " + *modePtr + " is not supported")
	}

}

//countProcsName look through the processlist and increment a counter when the process name
//is a direct match to the process given to us.
// it consumes:
// the process name as a string,
// a bool to search process name, otherwise it will search the command line
// a bool to perform a regex match, otherwise it does an exact comparison
func countProcs(process string, searchProcessName bool, performRegex bool) int32 {
	var runningProcesses []string
	var _count = int32(0)
	if searchProcessName {
		//fmt.Println("getPidNames")
		runningProcesses, _ = getPidNames()
	} else {
		//fmt.Println("getPidCmd")
		if performRegex {
			//offset the counter by 1 when we are searching the commandline, and
			//performing a regex search to account for our process matching the regex
			// No longer necessary after removing our pid from the list
			//_count--
		}
		runningProcesses, _ = getPidCmd()
	}
	for _, procName := range runningProcesses {
		//if procName[1] == process[1] {
		if performRegex {
			match, _ := regexp.MatchString(process, procName)
			//fmt.Println("performing regex match:", process, procName, match)
			if match {
				_count++
			}
		} else {
			//fmt.Println("performing string equality comparison")
			if procName == process {
				_count++
			}
			//}
		}
	}
	return _count
}

func getPids() ([]string, error) {
	var ret []string
	d, err := os.Open("/proc")
	if err != nil {
		return nil, err

	}
	defer d.Close()
	//iterate through the proc directory
	//look for numerical directories representing running processes
	fnames, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	//for each
	for _, fname := range fnames {
		pid, err := strconv.ParseInt(fname, 10, 32)
		if err != nil {
			// if not numeric name, just skip
			continue
		} else {
			//we need to skip over our own pid and parent pid here.
			myPid := os.Getpid()
			pPid := os.Getppid()
			if pid == int64(myPid) {
				//fmt.Printf("not counting my pid: " + strconv.FormatInt(int64(myPid), 10))
			} else if pid == int64(pPid) {
				//fmt.Printf("not counting my ppid: " + strconv.FormatInt(int64(pPid), 10))
			} else {
				ret = append(ret, strconv.Itoa(int(pid)))
			}
		}
	}
	return ret, nil
}

func getPidCmd() ([]string, error) {
	var ret []string
	pids, _ := getPids()
	for _, pid := range pids {
		var args bytes.Buffer
		statPath := filepath.Join("/", "proc", pid, "cmdline")
		contents, _ := ioutil.ReadFile(statPath)
		bbuf := bytes.NewBuffer(contents)
		for {
			arg, err := bbuf.ReadBytes(0)
			if err == io.EOF {
				break
			}
			args.WriteString(string(arg) + " ")
		}
		//fmt.Println(args.String())
		ret = append(ret, args.String())
	}
	return ret, nil
}
func getPidNames() ([]string, error) {
	var ret []string
	var pidName string

	pids, _ := getPids()
	for _, pid := range pids {
		//pid, err := strconv.ParseInt(fname, 10, 32)
		//		if err != nil {
		//			// if not numeric name, just skip
		//			continue
		//		}
		//generate the path for the process' status file
		statPath := filepath.Join("/", "proc", pid, "status")
		contents, err := ioutil.ReadFile(statPath)
		if err != nil {
			//return err
			//Since we're not looking at just one process,
			//we want to keep iterating if we don't get a status here.
			//
			continue
		} else {
			lines := strings.Split(string(contents), "\n")
			//we only care about the first line, which contains the name.
			nameLine := lines[0]
			tabParts := strings.SplitN(nameLine, "\t", 2)
			if len(tabParts) < 2 {
				continue
			}
			pidName = strings.Trim(tabParts[1], " \t")
			ret = append(ret, string(pidName))
		}
	}
	return ret, nil
}

//searchName switches whether we compare against the process name, or the process commandline.
//regexSearch switches whether to perform a regex search for the given processname, or if we want an exact match
//exit with a return code of 0. 1 if there's no match. we may exit with a value greater than 1 to indicate a non-exact match
func boolproc(process string,searchName bool, regexSearch bool){
	count := countProcs(process, searchName, regexSearch)
  if count > 0 {
    os.Exit(0)
	}	else {
	  os.Exit(1)
	}

}
//searchName switches whether we compare against the process name, or the process commandline.
//regexSearch switches whether to perform a regex search for the given processname, or if we want an exact match
func check(process string, warnMin int, warnMax int, critMin int, critMax int, searchName bool, regexSearch bool) {
	check := nagiosplugin.NewCheck()
	// Make sure the check always (as much as possible) exits with
	// the correct output and return code if we terminate unexpectedly.
	defer check.Finish()

	count := countProcs(process, searchName, regexSearch)

	value := float64(count)

	// Add some perfdata too (label, unit, value, min, max, warn, crit).
	check.AddPerfDatum(process, "", value, float64(critMin), math.Inf(1), float64(warnMax), float64(critMax))

	//check to see if we have more processes than critical minimum
	//generate critical if we are less than critical minimum
	//if we are above minimum critical threshold, check to see if we have more
	//processes than minimum warning level. generate warning if not.
	if count < int32(critMin) {
		nagiosplugin.Exit(nagiosplugin.CRITICAL, "Found "+fmt.Sprintf("%d", count)+" "+string(process)+" processes. Expecting "+fmt.Sprintf("%d", critMin))
	} else {
		if count < int32(warnMin) {
			nagiosplugin.Exit(nagiosplugin.WARNING, "Found "+fmt.Sprintf("%d", count)+" "+string(process)+" processes. Expecting "+fmt.Sprintf("%d", warnMin))

		}
	}
	if count > int32(critMax) {
		nagiosplugin.Exit(nagiosplugin.CRITICAL, "Found "+fmt.Sprintf("%d", count)+" "+string(process)+" processes. Max threshold: "+fmt.Sprintf("%d", critMax))
	} else {
		if count > int32(warnMax) {
			nagiosplugin.Exit(nagiosplugin.WARNING, "Found "+fmt.Sprintf("%d", count)+" "+string(process)+" processes. Warn threshold: "+fmt.Sprintf("%d", warnMax))

		}
	}
	//check to see if we have more processes than critical
	// Add an OK check result as the universe appears sane.
	check.AddResult(nagiosplugin.OK, "Everything looks shiny from here, cap'n")
	// We potentially perform more checks and add more results here;
	// if there's more than one, the highest result will be the one
	// returned (in ascending order OK, WARNING, CRITICAL, UNKNOWN).
}

//
//
func metric(process string, scheme string, searchName bool, regexSearch bool) {
	count := strconv.FormatInt(int64(countProcs(process, searchName, regexSearch)), 10)
	epochTime := strconv.FormatInt(int64(time.Now().Unix()), 10)
	fmt.Println(scheme + "\t" + count + "\t" + epochTime)
}
