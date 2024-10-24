package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Which string

const (
	Svc  Which = "svc"
	Self Which = "self"
)

type Update struct {
	Time      time.Time // Time at which update can be done.
	Which     Which     // "svc" or "self"
	ModPath   string    // E.g. "github.com/mjl-/moxtools"
	PkgDir    string    // E.g. "/" or "/cmd/somecommand".
	Version   string    // E.g. "v0.1.2"
	GoVersion string    // E.g. "go1.23.2"
}

func parseScheduledTxt(r io.Reader) (l []Update, rerr error) {
	text, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read: %v", err)
	}
	for _, e := range strings.Split(strings.TrimRight(string(text), "\n"), "\n") {
		t := strings.Split(e, " ")
		if len(t) != 6 {
			return nil, fmt.Errorf("bad line %q", e)
		}
		tm, err := time.Parse(time.RFC3339, t[0])
		if err != nil {
			return nil, fmt.Errorf("parsing time: %v", err)
		}
		switch t[1] {
		case "self", "svc":
		default:
			return nil, fmt.Errorf("parsing which, got %q", t[1])
		}
		l = append(l, Update{tm, Which(t[1]), t[2], t[3], t[4], t[5]})
	}
	return l, nil
}

func readScheduledTxt() ([]Update, error) {
	buf, err := os.ReadFile(filepath.Join(cacheDir, "scheduled.txt"))
	if err != nil {
		return nil, fmt.Errorf("read scheduled.txt: %w", err)
	}
	return parseScheduledTxt(bytes.NewReader(buf))
}

func writeScheduledTxt(l []Update) error {
	if len(l) == 0 {
		err := os.Remove(filepath.Join(cacheDir, "scheduled.txt"))
		if err != nil && errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return err
	}
	var b bytes.Buffer
	for _, u := range l {
		if _, err := fmt.Fprintf(&b, "%s %s %s %s %s %s\n", u.Time.Format(time.RFC3339), u.Which, u.ModPath, u.PkgDir, u.Version, u.GoVersion); err != nil {
			return fmt.Errorf("write: %v", err)
		}
	}
	return os.WriteFile(filepath.Join(cacheDir, "scheduled.txt"), b.Bytes(), 0600)
}

type Schedule []DayHour

type DayHour struct {
	Days  []time.Weekday
	Hours []int
}

// Next returns the first time >= now that matches the schedule.
func (s Schedule) Next(now time.Time) time.Time {
	if len(s) == 0 {
		return now
	}

	nowhour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.Local)

	// Stupid brute force through all options.
	var first time.Time
	for _, dh := range s {
		for _, d := range dh.Days {
			dt := now
			for dt.Weekday() != d {
				dt = dt.AddDate(0, 0, 1)
			}
			for _, h := range dh.Hours {
				ht := time.Date(dt.Year(), dt.Month(), dt.Day(), h, 0, 0, 0, time.Local)
				if ht.Equal(nowhour) {
					ht = now
				} else if ht.Before(now) {
					ht = time.Date(dt.Year(), dt.Month(), dt.Day()+7, h, 0, 0, 0, time.Local)
				}
				if first.IsZero() || ht.Before(first) {
					first = ht
				}
			}
		}
	}
	return first
}

func (sched *Schedule) UnmarshalText(buf []byte) (rerr error) {
	s := string(buf)
	var r Schedule
	for _, dhs := range strings.Split(s, ";") {
		dhs = strings.TrimSpace(dhs)
		if dhs == "" {
			return fmt.Errorf("empty day-hours")
		}
		t := strings.Split(dhs, " ")
		if len(t) > 2 || t[0] == "" || (len(t) == 2 && t[1] == "") {
			return fmt.Errorf("too many spaces in day-hours %q", dhs)
		}

		var err error

		var days []time.Weekday
		if !(t[0][0] >= '0' && t[0][0] <= '9') {
			days, err = parseDays(t[0])
			if err != nil {
				return fmt.Errorf("parsing days: %v", err)
			}
			t = t[1:]
		} else {
			days = []time.Weekday{
				time.Sunday,
				time.Monday,
				time.Tuesday,
				time.Wednesday,
				time.Thursday,
				time.Friday,
				time.Saturday,
			}
		}

		var hours []int
		if len(t) == 0 {
			hours = make([]int, 24)
			for i := 0; i < 24; i++ {
				hours[i] = i
			}
		} else {

			hours, err = parseHours(t[0])
			if err != nil {
				return fmt.Errorf("bad hours: %v", err)
			}
		}

		r = append(r, DayHour{days, hours})
	}
	*sched = r
	return nil
}

func (sched *Schedule) MarshalText() ([]byte, error) {
	if len(*sched) == 0 {
		return []byte(""), nil
	}
	// Not needed at the moment.
	return nil, fmt.Errorf("marshal for non-zero schedule not implemented")
}

var weekdays = map[string]time.Weekday{
	"su": time.Sunday,
	"mo": time.Monday,
	"tu": time.Tuesday,
	"we": time.Wednesday,
	"th": time.Thursday,
	"fr": time.Friday,
	"sa": time.Saturday,
}

func parseDays(s string) (days []time.Weekday, rerr error) {
	for _, e := range strings.Split(s, ",") {
		t := strings.Split(e, "-")
		if len(t) > 2 {
			return nil, fmt.Errorf("too many dashes in %q", e)
		}
		start, ok := weekdays[t[0]]
		if !ok {
			return nil, fmt.Errorf("unknown weekday %q", t[0])
		}
		if len(t) == 1 {
			days = append(days, start)
			continue
		}
		end, ok := weekdays[t[1]]
		if !ok {
			return nil, fmt.Errorf("unknown weekday %q", t[1])
		}
		for {
			days = append(days, start)
			if start == end {
				break
			}
			start = (start + 1) % time.Weekday(len(weekdays))
		}
	}
	return days, nil
}

func parseHours(s string) (hours []int, rerr error) {
	for _, e := range strings.Split(s, ",") {
		t := strings.Split(e, "-")
		if len(t) > 2 {
			return nil, fmt.Errorf("too many dashes in %q", e)
		}
		start, err := strconv.ParseUint(t[0], 10, 32)
		if err == nil && start >= 24 {
			err = fmt.Errorf("hour must be between 0 and 23")
		}
		if err != nil {
			return nil, fmt.Errorf("parsing hour %q: %v", t[0], err)
		}
		if len(t) == 1 {
			hours = append(hours, int(start))
			continue
		}
		end, err := strconv.ParseUint(t[1], 10, 32)
		if err == nil && end >= 24 {
			err = fmt.Errorf("hour must be between 0 and 23")
		} else if err == nil && end <= start {
			err = fmt.Errorf("for hour range, end must be larger than start")
		}
		if err != nil {
			return nil, fmt.Errorf("parsing hour %q: %v", t[1], err)
		}
		for ; start <= end; start++ {
			hours = append(hours, int(start))
		}
	}
	return hours, nil
}
